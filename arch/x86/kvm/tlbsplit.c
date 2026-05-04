/*
 * tlbsplit.c
 *
 *  Created on: Dec 28, 2015
 *      Author: nick
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
/*
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
*/
#include <linux/tlbsplit.h>
#include <asm/vmx.h>
#include <linux/debugfs.h>
#include <linux/miscdevice.h>
#include <linux/kvm_host.h>
//#include <linux/gfp.h>
#include <kvm_emulate.h>
#include "mmu.h"
#include "x86.h"

#include "winntstruct.h"


static void split_tlb_allow_thp(struct kvm *kvm, gpa_t gpa);
static void split_tlb_shatter_thp(struct kvm_vcpu *vcpu, gpa_t gpa);
unsigned long long split_tlb_safe_deref(unsigned long long * ptr);

static int tlbsplit_buffer_size = 0x200 ;
module_param(tlbsplit_buffer_size, int, 0);
MODULE_PARM_DESC(tlbsplit_buffer_size, "Number of entries in the tlb split debug buffer");
static int tlbsplit_emulate_on_violation = 0x0 ;
module_param(tlbsplit_emulate_on_violation, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(tlbsplit_emulate_on_violation, "On page flip 0-just retry 1-emulate instruction");
static long tlbsplit_magic = 0x0 ;
module_param(tlbsplit_magic, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(tlbsplit_magic, "Check rdx for this value in tlb split calls. Ignored if zero");
static int tlbsplit_log_read_stacks = 0x0 ;
module_param(tlbsplit_log_read_stacks, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(tlbsplit_log_read_stacks, "Log up to 5 stack pages of read flips into a file");

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))

#define PTE_WRITE (1<<1)
#define PTE_READ (1<<0)
#define PTE_EXECUTE (1<<2)

//#define KVM_MAX_TRACKER 0x200

atomic_t split_tracker_next_write;
struct kvm_ept_violation_tracker *split_tracker;

static struct dentry *split_dentry;

static size_t debug_buffer_size;

static int next_vm;

/* read file operation */
static ssize_t split_counter_reader(struct file *fp, char __user *user_buffer,
                                size_t count, loff_t *position)
{
     return simple_read_from_buffer(user_buffer, count, position, split_tracker, debug_buffer_size);
}

static const struct file_operations split_debug = {
        .read = split_counter_reader,
};

static struct miscdevice split_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "tlb_split",
	.fops = &split_debug,
	.mode = 0444,
};

void split_init_debugfs(void) {
	debug_buffer_size = sizeof(int) + sizeof(struct kvm_ept_violation_tracker_entry) * tlbsplit_buffer_size;
	atomic_set(&split_tracker_next_write,0);

	split_tracker = kzalloc(debug_buffer_size, GFP_KERNEL);

	split_tracker->max_number_of_entries = tlbsplit_buffer_size;
	split_dentry = debugfs_create_file("tlb_split", 0444, kvm_debugfs_dir, NULL, &split_debug);
	printk(KERN_INFO "tlb_split_init:debugfs_create_file returned 0%lx allocated:0%ld for %d entries\n",(unsigned long)split_dentry,debug_buffer_size,tlbsplit_buffer_size);
	
	misc_register(&split_miscdev);
	next_vm = 0;
}

static void split_tlb_register_ept_flip(gva_t gva, gva_t rip, unsigned long cr3, struct kvm *kvm, bool read) {
	int vmnumber = kvm->splitpages->vmcounter;
	unsigned int counter = atomic_inc_return(&split_tracker_next_write);
	unsigned int nextRow = (counter - 1) % (unsigned int)split_tracker->max_number_of_entries;
	if (gva >= kvm->splitpages->adjust_from && gva <= kvm->splitpages->adjust_to) 
		split_tracker->entries[nextRow].gva = gva - kvm->splitpages->adjust_by;
	else
		split_tracker->entries[nextRow].gva = gva;
	if (rip >= kvm->splitpages->adjust_from && rip <= kvm->splitpages->adjust_to) 
		split_tracker->entries[nextRow].rip = rip - kvm->splitpages->adjust_by;
	else
		split_tracker->entries[nextRow].rip = rip;
	split_tracker->entries[nextRow].cr3 = cr3;
	split_tracker->entries[nextRow].vmnumber = vmnumber;
	split_tracker->entries[nextRow].read = read;
	split_tracker->entries[nextRow].counter = counter;
}

void split_shutdown_debugfs(void) {
	debugfs_remove(split_dentry);
	misc_deregister(&split_miscdev);
	kfree(split_tracker);
}

void split_tlb_unprotect_pte(struct kvm *kvm, struct kvm_splitpage *page)
{
	struct kvm_memory_slot *slot;

	spin_lock(&kvm->splitpages->track_lock);
	if (!page->pte_tracking_active) {
		spin_unlock(&kvm->splitpages->track_lock);
		return;
	}

	slot = gfn_to_memslot(kvm, page->pte_gfn);
	if (slot) {
		kvm_slot_page_track_remove_page(kvm, slot, page->pte_gfn, KVM_PAGE_TRACK_WRITE);
		//printk(KERN_INFO "split_tlb: PTE write-protection removed for PTE GPA: 0x%llx\n", page->pte_gpa);
	}

	page->pte_tracking_active = false;
	spin_unlock(&kvm->splitpages->track_lock);
}

void split_tlb_protect_pte(struct kvm_vcpu *vcpu, struct kvm_splitpage *page, gpa_t pte_gpa)
{
	struct kvm_memory_slot *slot;
	gfn_t pte_gfn = pte_gpa >> PAGE_SHIFT;

	spin_lock(&vcpu->kvm->splitpages->track_lock);
	if (page->pte_tracking_active) {
		spin_unlock(&vcpu->kvm->splitpages->track_lock);
		return;
	}

	slot = kvm_vcpu_gfn_to_memslot(vcpu, pte_gfn);
	if (!slot) {
		spin_unlock(&vcpu->kvm->splitpages->track_lock);
		return;
	}

	page->pte_gpa = pte_gpa;
	page->pte_gfn = pte_gfn;
	page->pte_tracking_active = true;

	kvm_slot_page_track_add_page(vcpu->kvm, slot, pte_gfn, KVM_PAGE_TRACK_WRITE);
	//printk(KERN_INFO "split_tlb: PTE write-protection activated for PTE GPA: 0x%llx\n", pte_gpa);
	spin_unlock(&vcpu->kvm->splitpages->track_lock);
}
EXPORT_SYMBOL_GPL(split_tlb_protect_pte);

bool tlb_split_init(struct kvm *kvm) {
	kvm->splitpages = kzalloc(sizeof(struct kvm_splitpages), GFP_KERNEL);
	if (kvm->splitpages!=NULL) {
		kvm->splitpages->vmcounter = next_vm++;
		spin_lock_init(&kvm->splitpages->track_lock);
		return true;
	}
	else
		return false;
}

void kvm_split_tlb_freepage(struct kvm *kvm, struct kvm_splitpage *page)
{
	gpa_t old_gpa = 0;
	void *data, *code;
	split_tlb_unprotect_pte(kvm, page);
	/* Drop the THP restriction if this page was ever activated */
	spin_lock(&kvm->splitpages->track_lock);
	if (page->gpa != 0) {
		old_gpa = page->gpa;
		page->gpa = 0;
	}
	page->cr3 = 0;
	page->pte_gpa = 0;
	page->pte_gfn = 0;
	page->active = false;

	data = page->dataaddr;
	code = page->codepage;
	page->dataaddr = NULL;
	page->codepage = NULL;

	page->gva = 0;
	page->codeaddr = 0;
	page->mtf_exits = 0;
	page->dataaddrphys = 0;
	spin_unlock(&kvm->splitpages->track_lock);

	if (old_gpa != 0)
		split_tlb_allow_thp(kvm, old_gpa);
	if (data)
		kfree(data);
	if (code)
		kfree(code);
}
EXPORT_SYMBOL_GPL(kvm_split_tlb_freepage);

void kvm_split_tlb_deactivateall(struct kvm *kvm) {
	struct kvm_splitpages *spages = kvm->splitpages;
	int i;

	if (!spages) {
		printk(KERN_WARNING "split_tlb: spages is NULL in kvm_split_tlb_deactivateall!\n");
		return;
	}

	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++)
		kvm_split_tlb_freepage(kvm, &spages->pages[i]);
	kfree(kvm->splitpages);
}
EXPORT_SYMBOL_GPL(kvm_split_tlb_deactivateall);

static struct kvm_splitpage* split_tlb_findpage_internal(struct kvm *kvms,gpa_t gpa) {
	int i;
	struct kvm_splitpage* found;
	gpa_t pagestart;

	if (!kvms->splitpages) {
		printk(KERN_WARNING "split_tlb: splitpages is NULL in _split_tlb_findpage!\n");
		return NULL;
	}

	pagestart = gpa&PAGE_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->gpa == pagestart)
			return found;
	}
	return NULL;
}

struct kvm_splitpage* split_tlb_findpage(struct kvm *kvms,gpa_t gpa) {
	if (gpa&PAGE_MASK)
		return split_tlb_findpage_internal(kvms,gpa);
	else
		return NULL;
}
EXPORT_SYMBOL_GPL(split_tlb_findpage);

struct kvm_splitpage* split_tlb_findpage_gva_cr3(struct kvm *kvms, gva_t gva, ulong cr3) {
	struct kvm_splitpage* found;
	gva_t pagestart;
	int i;

	if (!kvms->splitpages) {
		printk(KERN_WARNING "split_tlb: splitpages is NULL in split_tlb_findpage_gva_cr3!\n");
		return NULL;
	}

	pagestart = gva&PAGE_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->gva == pagestart && found->cr3 == cr3)
			return found;
	}
	return NULL;
}


int split_tlb_setdatapage(struct kvm_vcpu *vcpu, gva_t gva, gva_t datagva, ulong cr3) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	gpa_t translated;
	int r;
	access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split_tlb_setdatapage: gva:0x%lx gpa not found %d vm:%x\n",gva,exception.error_code, vcpu->kvm->splitpages->vmcounter);
		gpa = 0;
	}
	printk(KERN_INFO "split_tlb_setdatapage: cr3:0x%lx gva:0x%lx gpa:0x%llx vm:%x\n",cr3,gva,gpa, vcpu->kvm->splitpages->vmcounter);
	if (gpa!=0)
		page = split_tlb_findpage(vcpu->kvm,gpa);
	else
		page = split_tlb_findpage_gva_cr3(vcpu->kvm,gva,cr3);
	if (page == NULL) {
		int i;
		spin_lock(&vcpu->kvm->splitpages->track_lock);
		for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
			if (vcpu->kvm->splitpages->pages[i].gva == 0) {
				page = &vcpu->kvm->splitpages->pages[i];
				page->gva = gva & PAGE_MASK; /* Claim it atomically! */
				break;
			}
		}
		spin_unlock(&vcpu->kvm->splitpages->track_lock);

		if (page == NULL) {
			printk(KERN_WARNING "No more slots in the split page table vm:%x\n", vcpu->kvm->splitpages->vmcounter);
			return 0;
		}
		page->cr3 = cr3;
		page->gpa = gpa&PAGE_MASK;
		split_tlb_shatter_thp(vcpu, page->gpa);
		page->dataaddr = kmalloc(4096,GFP_KERNEL);
		page->dataaddrphys = virt_to_phys(page->dataaddr);
		page->codepage = kmalloc(4096,GFP_KERNEL);
		page->codeaddr = virt_to_phys(page->codepage);
		BUG_ON(((long unsigned int)page->dataaddr&~PAGE_MASK)!=0);
		BUG_ON(((long unsigned int)page->codepage&~PAGE_MASK)!=0);
		translated = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, datagva&PAGE_MASK, access, &exception);
		if (translated == UNMAPPED_GVA) {
			printk(KERN_WARNING "split:tlb_setdatapage gva:0x%lx gpa not found for data %d vm:%x\n",datagva,exception.error_code, vcpu->kvm->splitpages->vmcounter);
			return 0;
		}
		r = kvm_read_guest(vcpu->kvm,translated,page->dataaddr,4096);
		memcpy(page->codepage,page->dataaddr,4096);
		printk(KERN_INFO "split:tlb_setdatapage cr3:0x%lx gva:0x%lx gpa:0x%llx data:0x%llx/0x%llx code:0x%llx/0x%llx copy result:%d vm:%x\n",cr3,gva,gpa,(u64)page->dataaddr,virt_to_phys(page->dataaddr),(u64)page->codepage,virt_to_phys(page->codepage),r, vcpu->kvm->splitpages->vmcounter);
	} else {
		printk(KERN_WARNING "Already a page for: gpa:0x%llx with cr3:0x%lx and gva=0x%lx vm:%x\n",gpa,page->cr3,page->gva, vcpu->kvm->splitpages->vmcounter);
		return 0;
	}
	return 1;
}
//EXPORT_SYMBOL_GPL(split_tlb_setdatapage);

int split_tlb_findspte_callback(u64* sptep, int level, int last, int large) {
	return (last && !large);
}

int split_tlb_findspte_large_callback(u64* sptep, int level, int last, int large) {
	return (last && large);
}

int split_tlb_findspte_callback_print(u64* sptep, int level, int last, int large) {
	printk(KERN_WARNING "split_tlb_findspte: sptep 0x%llx level:%d large=%d last=%d \n",*sptep,level,large,last);
	return (last && !large);
}

static void split_tlb_allow_thp(struct kvm *kvm, gpa_t gpa)
{
	struct kvm_memory_slot *slot;
	if (!gpa)
		return;
	slot = gfn_to_memslot(kvm, gpa >> PAGE_SHIFT);
	if (slot) {
		spin_lock(&kvm->mmu_lock);
		kvm_mmu_gfn_allow_lpage(slot, gpa >> PAGE_SHIFT);
		spin_unlock(&kvm->mmu_lock);
	}
}

static void split_tlb_shatter_thp(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	u64 *sptep;
	struct kvm_memory_slot *slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);

	if (!gpa)
		return;

	if (!slot)
		return;

	spin_lock(&vcpu->kvm->mmu_lock);
	/* 1. Unconditionally prevent KVM from using large pages for this 2MB range */
	kvm_mmu_gfn_disallow_lpage(slot, gfn);
	/* 2. Check if it is currently mapped as a large page */
	sptep = split_tlb_findspte(vcpu, gfn, split_tlb_findspte_large_callback);
	spin_unlock(&vcpu->kvm->mmu_lock);
		/* 3. If it is actively mapped as large, zap and rebuild it */
	if (sptep != NULL) {
		printk(KERN_INFO "split_tlb: Shattering active THP 2MB page at GPA 0x%llx\n", gpa);
		kvm_zap_gfn_range(vcpu->kvm, gfn, gfn + 1);
		kvm_mmu_page_fault(vcpu, gpa, 0, NULL, 0);
	}
}

static gpa_t get_guest_pte_gpa(struct kvm_vcpu *vcpu, unsigned long cr3, gva_t gva) {
	int level;
	gpa_t table_gpa = cr3 & PT64_BASE_ADDR_MASK;
	gpa_t pte_gpa = 0;
	u64 pte;

	/* Standard 4-level paging for 64-bit Windows */
	for (level = 4; level >= 1; level--) {
		int shift = (level - 1) * 9 + 12;
		pte_gpa = table_gpa + ((gva >> shift) & 0x1ff) * 8;
		if (kvm_read_guest(vcpu->kvm, pte_gpa, &pte, sizeof(pte)))
			return 0;
		if (!(pte & 1ULL)) /* Not present */
			return 0;
		if (level > 1 && (pte & (1ULL << 7))) { /* Large page */
			printk_ratelimited(KERN_INFO "split_tlb: Guest is using %s Large Page for GVA 0x%lx!\n",
					   level == 3 ? "1GB" : "2MB", gva);
			return pte_gpa;
		}
		table_gpa = pte & PT64_BASE_ADDR_MASK;
	}
	return pte_gpa;
}

int split_tlb_activatepage(struct kvm_vcpu *vcpu, gva_t gva, ulong cr3) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	u64* sptep;
	int result = 0;
	//struct kvm_shadow_walk_iterator iterator;
	gfn_t gfn;
	gpa_t old_gpa = 0;
	bool gpa_changed = false;

	access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split:split_tlb_activatepage gva:0x%lx gpa not found %d vm:%x\n",gva,exception.error_code, vcpu->kvm->splitpages->vmcounter);
		return 0;
	}
	page = split_tlb_findpage_gva_cr3(vcpu->kvm,gva,cr3);
	if (page == NULL) {
		printk(KERN_WARNING "split:tlb_activatepage page not foundcr3:0x%lx gva:0x%lx translated gpa:0x%llx vm:%x\n",cr3,gva,gpa, vcpu->kvm->splitpages->vmcounter);
		return 0;
	}
	printk(KERN_INFO "split_tlb_activatepage found page cr3:0x%lx gva:0x%lx gpa:0x%llx page_gpa:0x%llx vm:%x\n",cr3,gva,gpa,page->gpa, vcpu->kvm->splitpages->vmcounter);
	spin_lock(&vcpu->kvm->splitpages->track_lock);
	if (page->gpa != (gpa&PAGE_MASK)) {
		old_gpa = page->gpa;
		page->gpa = gpa&PAGE_MASK;
		gpa_changed = true;
	}
	spin_unlock(&vcpu->kvm->splitpages->track_lock);

	if (gpa_changed) {
		if (old_gpa != 0)
			split_tlb_allow_thp(vcpu->kvm, old_gpa);
		printk(KERN_WARNING "split:tlb_activatepage gpa changed 0x%llx->0x%llx, adjusting vm:%x\n",old_gpa,gpa&PAGE_MASK, vcpu->kvm->splitpages->vmcounter);
		split_tlb_shatter_thp(vcpu, page->gpa);
	}

	gfn = gpa >> PAGE_SHIFT;

	spin_lock(&vcpu->kvm->mmu_lock);
	page->active = true;
	sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
	if (sptep!=NULL) {
		u64 newspte = *sptep & ~(VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK);
		page->original_spte = *sptep;
		newspte&=~PT64_BASE_ADDR_MASK;
		newspte|=page->codeaddr&PT64_BASE_ADDR_MASK;
		//newspte = 0L;
		printk(KERN_INFO "split_tlb_activatepage: spte=0x%llx->newspte=0x%llx ,sptep=x%llx vm:%x\n",*sptep,newspte,(u64)sptep, vcpu->kvm->splitpages->vmcounter);
        	*sptep = newspte;
		kvm_flush_remote_tlbs(vcpu->kvm);
		result = 1;
	} else {
		printk(KERN_INFO "split_tlb_activatepage: spte not found 0x%llx, hook will arm on next access vm:%x\n",gpa, vcpu->kvm->splitpages->vmcounter);
		result = 1;
	}
	spin_unlock(&vcpu->kvm->mmu_lock);

	if (result) {
		gpa_t pte_gpa = get_guest_pte_gpa(vcpu, cr3, gva);
		if (pte_gpa) {
			/* Hybrid Approach: Record coordinates but leave EPT shield OFF */
			split_tlb_unprotect_pte(vcpu->kvm, page);
			page->pte_gpa = pte_gpa;
			page->pte_gfn = pte_gpa >> PAGE_SHIFT;
			page->pte_tracking_active = false;
		} else {
			printk(KERN_WARNING "split_tlb: Failed to find guest PTE GPA for GVA: 0x%lx, PTE tracking NOT activated! vm:%x\n", gva, vcpu->kvm->splitpages->vmcounter);
		}
	}

	return result;
}
//EXPORT_SYMBOL_GPL(split_tlb_activatepage);

int split_tlb_copymem(struct kvm_vcpu *vcpu, gva_t from, gva_t to, u64 count, ulong cr3) {
	printk(KERN_INFO "split_tlb_copymem: from:0x%lx to:%lx count:%lld cr3:%lx vm:%x\n",from,to,count,cr3, vcpu->kvm->splitpages->vmcounter);
	if (count>MAX_PATCH_SIZE)
		return 0;
	else {
		int r,result;
		char * buf = kmalloc(count,GFP_KERNEL);
		u64 remains = count;
		struct x86_exception exception;
		u32 access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
		gpa_t from_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, from, access, &exception);
		//gpa_t to_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, to, access, &exception);
		if (from_gpa == UNMAPPED_GVA) {
			printk(KERN_WARNING "split_tlb_copymem: from gva:0x%lx gpa not found %d vm:%x\n",from,exception.error_code, vcpu->kvm->splitpages->vmcounter);
			result = 0;
			goto return_label;
		}
/*		if (to_gpa == UNMAPPED_GVA) {
			printk(KERN_WARNING "split_tlb_copymem: to gva:0x%lx gpa not found  %d\n",to,exception.error_code);
			return 0;
		}
*/
		r = kvm_read_guest(vcpu->kvm,from_gpa,buf,count);
		if (r != 0) {
			printk(KERN_WARNING "split_tlb_copymem: read gva:0x%lx gpa:0x%llx failed with the result %d vm:%x\n",from,from_gpa,r, vcpu->kvm->splitpages->vmcounter);
			result = 0;
			goto return_label;
		}
		while (remains > 0) {
			gva_t cur_gva = to+(count-remains);
			struct kvm_splitpage* page = split_tlb_findpage_gva_cr3(vcpu->kvm,cur_gva,cr3);
			u64 to_copy;
			u64 page_offset = cur_gva & (PAGE_SIZE - 1);
			char *to_addr;
			char *from_addr = buf+(count-remains);
			if (page == NULL) {
				printk(KERN_WARNING "split_tlb_copymem: split page not found gva:0x%lx remains:%lld count:%lld vm:%x\n",to,remains,count, vcpu->kvm->splitpages->vmcounter);
				result = 0;
				goto return_label;
			}
			if ( ( cur_gva & PAGE_MASK ) == ((cur_gva+remains) & PAGE_MASK ) ) {
				to_copy = remains;
				remains = 0;
			} else {
				to_copy = ( cur_gva & PAGE_MASK ) + PAGE_SIZE - cur_gva;
				remains -= to_copy;
			}
			to_addr = ((char*)(page->codepage)) + page_offset;
			printk(KERN_INFO "split_tlb_copymem: copying %lld bytes to gva:0x%lx/hva:0x%llx vm:%x\n",to_copy,cur_gva,(u64)to_addr, vcpu->kvm->splitpages->vmcounter);
			memcpy(to_addr,from_addr,to_copy);
		}
		result = 1;
return_label:
        kfree(buf);		
		return result;
	}
}

int split_tlb_setadjuster(struct kvm_vcpu *vcpu, gva_t from, gva_t to, u64 by) {
	vcpu->kvm->splitpages->adjust_from = from;
	vcpu->kvm->splitpages->adjust_to = to;
	vcpu->kvm->splitpages->adjust_by = by;
	printk(KERN_DEBUG "split_tlb_setadjuster: from:0x%lx to:0x%lx by 0x%llx vm:0x%x\n",from,to,by,vcpu->kvm->splitpages->vmcounter);
	return 1;
}

int split_tlb_restore_spte_atomic(struct kvm *kvms,gfn_t gfn,u64* sptep,hpa_t stepaddr) {
	if (sptep!=NULL) {
		u64 newspte = *sptep;
		if ((newspte&VMX_EPT_READABLE_MASK)==0||(newspte&VMX_EPT_EXECUTABLE_MASK)==0||(newspte&VMX_EPT_WRITABLE_MASK)==0) {
			newspte|=VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=stepaddr & PT64_BASE_ADDR_MASK;
			printk(KERN_WARNING "split_tlb_restore_spte_atomic: fixing spte 0%llx->0%llx for 0%llx\n", *sptep, newspte, gfn<<PAGE_SHIFT);
			*sptep = newspte;
		} else
			printk(KERN_WARNING "split_tlb_restore_spte_atomic: spte for 0%llx seems untouched: 0%llx\n", gfn<<PAGE_SHIFT, *sptep);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_restore_spte_atomic: spte not found for 0x%llx\n", gfn<<PAGE_SHIFT);
		return 0;
	}
}

hpa_t ts_gfn_to_pfa(struct kvm_vcpu *vcpu,gfn_t gfn) {
struct kvm_memory_slot *slot;
bool async,writable;
kvm_pfn_t pfn;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	async = false;
	pfn = __gfn_to_pfn_memslot(slot, gfn, false, &async, false, &writable);
	WARN(async, "ts_gfn_to_pfn: unexpected async:%d\n", async);
	return pfn << PAGE_SHIFT;
	
}

int split_tlb_restore_spte(struct kvm_vcpu *vcpu,gfn_t gfn,struct kvm_splitpage* page) {
	int result;
	u64* sptep;
	hpa_t stepaddr = ts_gfn_to_pfa(vcpu,gfn) ;
	spin_lock(&vcpu->kvm->mmu_lock);
	sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
	if (page->active) {
		page->active = false;
		if (( page->original_spte & PT64_BASE_ADDR_MASK ) == 0) {
			printk(KERN_WARNING "split_tlb_restore_spte: page faulted at 0, restoring it to zero and falling back:0%llx\n", gfn<<PAGE_SHIFT);
			if (sptep)
				*sptep = 0; 
			result = 0;
		} else {
			if (sptep!=NULL && *sptep==0) {
//				spin_unlock(&vcpu->kvm->mmu_lock);
				printk(KERN_WARNING "split_tlb_restore_spte: zero spte, falling back to default handler gpa:0%llx\n", gfn<<PAGE_SHIFT);
				result = 0;
				goto unlockexit;
			}
			result = split_tlb_restore_spte_atomic(vcpu->kvm,gfn,sptep,stepaddr);
		}
	} else {
		printk(KERN_WARNING "split_tlb_restore_spte: hit inactive page gpa:0%llx\n", gfn<<PAGE_SHIFT);
		result = 1;
	}
	
unlockexit:	
	
	spin_unlock(&vcpu->kvm->mmu_lock);
	return result;
}

/*
int split_tlb_flip_to_code(struct kvm *kvms,hpa_t hpa,u64* sptep) {
	if (sptep!=NULL) {
		u64 newspte = *sptep;
		if ((newspte&VMX_EPT_READABLE_MASK)!=0||(newspte&VMX_EPT_EXECUTABLE_MASK)==0||(newspte&VMX_EPT_WRITABLE_MASK)==0) {
			WARN_ON(hpa==0);
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_READABLE_MASK);
			newspte|=VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=hpa&PT64_BASE_ADDR_MASK;
			printk(KERN_WARNING "split_tlb_flip_to_code: fixing spte 0%llx->0%llx for 0%llx\n", *sptep, newspte, hpa);
			*sptep = newspte;
		} else
			printk(KERN_WARNING "split_tlb_flip_to_code: spte for 0%llx seems untouched: 0%llx\n", hpa, *sptep);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_flip_to_code: spte not found for hpa 0x%llx\n", hpa);
		return 0;
	}
}
*/


int split_tlb_freepage_by_gpa(struct kvm_vcpu *vcpu, gpa_t gpa) {
	gfn_t gfn;
	struct kvm_splitpage* page;

	spin_lock(&vcpu->kvm->splitpages->track_lock);
	page = split_tlb_findpage_internal(vcpu->kvm, gpa);
	if (page == NULL) {
		spin_unlock(&vcpu->kvm->splitpages->track_lock);
		printk(KERN_WARNING "split_tlb_freepage_by_gpa: page not found gpa:0x%llx vm:%x\n",gpa, vcpu->kvm->splitpages->vmcounter);
		return 0;
	}

	if (page->active) {
		gfn = gpa >> PAGE_SHIFT;
		split_tlb_restore_spte(vcpu, gfn, page);
		printk(KERN_INFO "split_tlb_freepage_by_gpa: deactivating cr3:0x%lx gva:0x%lx gpa:0x%llx vm:%x\n", page->cr3, page->gva, page->gpa, vcpu->kvm->splitpages->vmcounter);
	} else {
		printk(KERN_WARNING "split_tlb_freepage_by_gpa: inactive page cr3:0x%lx gva:0x%lx gpa:0x%llx vm:%x\n", page->cr3, page->gva, page->gpa, vcpu->kvm->splitpages->vmcounter);
	}
	spin_unlock(&vcpu->kvm->splitpages->track_lock);

	kvm_split_tlb_freepage(vcpu->kvm, page);
	return 1;
}

int split_tlb_freepage(struct kvm_vcpu *vcpu, gva_t gva) {
	gpa_t gpa;
	u32 access;
	struct x86_exception exception;

	access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA)
		printk(KERN_WARNING "split:tlb_freepage gva:0x%lx gpa not found %d vm:%x\n",gva,exception.error_code, vcpu->kvm->splitpages->vmcounter);

	return split_tlb_freepage_by_gpa(vcpu,gpa);
}

static int read_guest_by_virtual(struct kvm_vcpu *vcpu, gva_t from_gva, void* into, u64 count) {
	int r;
	struct x86_exception exception;
	u32 access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	u64 remaining = count;
	char* into_c = (char*) into;
	while (remaining>0) {
		gpa_t from_gpa;
		u64 copy_now;
		if ( ( (from_gva + remaining - 1) & PAGE_MASK ) != ( from_gva & PAGE_MASK ) ) {
			copy_now = ( ( from_gva + PAGE_SIZE ) & PAGE_MASK ) - from_gva;
		} else {
			copy_now = remaining;
	    }
		from_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, from_gva, access, &exception);	
		if (from_gpa == UNMAPPED_GVA) {
			printk(KERN_WARNING "read_guest_by_virtual: for gva:0x%lx gpa not found %d vm:%x\n",from_gva,exception.error_code, vcpu->kvm->splitpages->vmcounter);
			return 0;
		}
		r = kvm_read_guest(vcpu->kvm,from_gpa,into_c,copy_now);
		if (r != 0) {
			printk(KERN_WARNING "read_guest_by_virtual: read gva:0x%lx gpa:0x%llx failed with the result %d vm:%x\n",from_gva,from_gpa,r, vcpu->kvm->splitpages->vmcounter);
			return 0;
		}
		from_gva += copy_now;
		into_c += copy_now;
		remaining -= copy_now;
	}
	return 1;
}

#define MAX_PATH_LENGTH 4096

int split_tlb_procinfo(struct kvm_vcpu *vcpu,void* buf,uint buf_size,gva_t *user_stack) {
	struct kvm_segment gs;
	TEB guest_teb;
	PEB guest_peb;
	RTL_USER_PROCESS_PARAMETERS guest_upp;
	int guest_cpl = kvm_x86_ops.get_cpl(vcpu);
	gva_t guest_teb_addr;
	char* printbuf = (char*) buf;
	int printed;
	int remains = buf_size;
	
	memset(buf,0,buf_size);
	kvm_get_segment(vcpu, &gs, VCPU_SREG_GS);
	printed = scnprintf(printbuf,remains,"gs:(base=%llx,limit=%x,selector=%x) cpl:%d\n",gs.base,gs.limit,gs.selector,guest_cpl);
	printbuf += printed;
	remains -= printed;
	//printk(KERN_INFO "split_tlb_procinfo: gs:(base=%llx,limit=%x,selector=%x) cpl:%d\n",gs.base,gs.limit,gs.selector,guest_cpl);
	if (guest_cpl == 0) {
		struct msr_data kernel_gs_base;
		kernel_gs_base.index = 0xC0000102;
		kernel_gs_base.host_initiated = false;
		kvm_x86_ops.get_msr(vcpu,&kernel_gs_base);
		printed = scnprintf(printbuf,remains,"got MSR 0xC0000102 as %llx\n",kernel_gs_base.data);
		printbuf += printed;
		remains -= printed;
		//printk(KERN_INFO "split_tlb_procinfo: got MSR 0xC0000102 as %llx", kernel_gs_base.data);
		guest_teb_addr = kernel_gs_base.data;
		//0x1A8
		if (read_guest_by_virtual(vcpu,gs.base+0x10,user_stack,sizeof *user_stack) == 0) {
			printed = scnprintf(printbuf,remains,"Got error reading user stack\n");
			printbuf += printed;
			remains -= printed;
			*user_stack = 0;
		} else {
			printed = scnprintf(printbuf,remains,"User stack:%lx\n",*user_stack);
			printbuf += printed;
			remains -= printed;
		}
	} else if (guest_cpl == 3) {
		guest_teb_addr = gs.base;
		*user_stack = 0;
	} else {
		*user_stack = 0;
		return 0;
	}
	
	if (read_guest_by_virtual(vcpu,guest_teb_addr,&guest_teb,sizeof guest_teb) == 0)
		return 0;
		
	if (read_guest_by_virtual(vcpu,(gva_t)guest_teb.ProcessEnvironmentBlock,&guest_peb,sizeof guest_peb) == 0)
		return 0;

	if (read_guest_by_virtual(vcpu,(gva_t)guest_peb.ProcessParameters,&guest_upp,sizeof guest_upp) == 0)
		return 0;

	printed = scnprintf(printbuf,remains,"peb.ImageBase: %llx ImagePathName.length %d ImagePathName.buffer %llx\n", (u64)guest_peb.ImageBaseAddress, guest_upp.ImagePathName.Length, (u64)guest_upp.ImagePathName.Buffer);
	printbuf += printed;
	remains -= printed;

	//printk(KERN_INFO "split_tlb_procinfo: peb.ImageBase: %llx ImagePathName.length %d ImagePathName.buffer %llx\n", (u64)guest_peb.ImageBaseAddress, guest_upp.ImagePathName.Length, (u64)guest_upp.ImagePathName.Buffer);
	if (guest_upp.ImagePathName.Length < MAX_PATH_LENGTH) {
		WORD* buf = kmalloc(guest_upp.ImagePathName.Length*2, GFP_KERNEL);
		char* buf2 = kmalloc(guest_upp.ImagePathName.Length+1, GFP_KERNEL);
		int i;
		if (read_guest_by_virtual(vcpu,(gva_t)guest_upp.ImagePathName.Buffer,buf,guest_upp.ImagePathName.Length * 2) == 0) {
			kfree(buf2);
			kfree(buf);
			return 0;
		}
		for (i = 0; i < guest_upp.ImagePathName.Length; i++) {
			buf2[i] = (char)buf[i];
		}
		buf2 [guest_upp.ImagePathName.Length] = 0;
		printed = scnprintf(printbuf,remains,"image path=%s\n", buf2);
		printbuf += printed;
		remains -= printed;
		kfree(buf2);
		kfree(buf);
		//printk(KERN_INFO "split_tlb_procinfo: image path=%s\n",buf2);		
	} else { 
		printed = scnprintf(printbuf,remains,"iimage path too long, ignoring\n");
		printbuf += printed;
		remains -= printed;
		//printk(KERN_INFO "split_tlb_procinfo: image path too long, ignoring");
	}
	return 1;
}

static void print_stack_pages_to_log(struct kvm_vcpu *vcpu,struct file *file,int count, gva_t rsp, loff_t *pos, char * buffer) {
	int access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	int cntr, pages_printed = 0;
	gpa_t gpa;
	struct x86_exception exception;
	
	for (cntr=0; cntr < count; cntr++) {
		gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, (rsp+PAGE_SIZE*cntr)&PT64_BASE_ADDR_MASK, access, &exception);
		if (gpa == UNMAPPED_GVA) {
			break;
			//printk(KERN_WARNING "print_stack_pages_to_log: stack gva:0x%llx gpa not found %d\n",rsp&PT64_BASE_ADDR_MASK,exception.error_code);
		} else {
			pages_printed ++;
			if (kvm_read_guest_page(vcpu->kvm,gpa>>PAGE_SHIFT,buffer,0,0x1000))
				printk(KERN_WARNING "print_stack_pages_to_log: stack reading failed at gpa 0x%llx\n",gpa);
			else {
				if (cntr==0) {
					int bpos;
					for (bpos = 0; bpos < (rsp&0xFFF); bpos++)
						buffer[bpos] = 0xBE;
				}
				kernel_write(file, buffer, PAGE_SIZE, pos);
				//pos += PAGE_SIZE;
				//rsp += PAGE_SIZE;
			}
		}
	}
	printk(KERN_INFO "print_stack_pages_to_log: stack gva:0x%lx printed 0%d pages\n",rsp,pages_printed);
}

static void log_read_flip(struct kvm_vcpu *vcpu,unsigned long rip) {
	int i;
	bool found =false;
	if (tlbsplit_log_read_stacks == 0)
		return;
	for (i=0; i<KVM_SPLIT_PAGES_TRACKER_SIZE; i++) {
		if (vcpu->kvm->splitpages->gvas_logged[i]==rip) {
			found = true;
			break;
		}
	}
	if (found)
		return;
	for (i=0; i<KVM_SPLIT_PAGES_TRACKER_SIZE; i++) {
		if (vcpu->kvm->splitpages->gvas_logged[i]==0) {
			vcpu->kvm->splitpages->gvas_logged[i] = rip;
			found = true;
			break;
		}
	}
	if (found) {
		char * buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
		struct file *file;
		unsigned long rsp = kvm_register_read(vcpu, VCPU_REGS_RSP);

		mm_segment_t old_fs;
		loff_t pos = 0;

		old_fs = get_fs();  //Save the current FS segment PT64_BASE_ADDR_MASK
		set_fs(KERNEL_DS);
		if (buffer) {
			snprintf(buffer,PAGE_SIZE,"/var/tmp/vm0x%x_rip0x%lx.dmp",vcpu->kvm->splitpages->vmcounter,rip);
			printk(KERN_INFO "log_read_flip: logging details for rip 0x%lx rsp 0x%lx file:%s\n",rip,rsp,buffer);
			file = filp_open(buffer, O_WRONLY|O_CREAT, 0644);
			if (file && !IS_ERR(file)) {
				int access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
				struct x86_exception exception;
				gpa_t gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, rip&PT64_BASE_ADDR_MASK, access, &exception);
				if (gpa == UNMAPPED_GVA) {
					printk(KERN_WARNING "split log_read_flip: code gva:0x%llx gpa not found %d\n",rip&PT64_BASE_ADDR_MASK,exception.error_code);
				} else {
					int r;
					gva_t user_stack;
					printk(KERN_INFO "split log_read_flip: code gva:0x%llx gpa 0x%llx\n",rip&PT64_BASE_ADDR_MASK,gpa);
					r = kvm_read_guest_page(vcpu->kvm,gpa>>PAGE_SHIFT,buffer,0,0x1000);
					if (r)
						printk(KERN_WARNING "split log_read_flip: code reading failed at gpa 0x%llx\n",gpa);
					else {
						kernel_write(file, buffer, PAGE_SIZE, &pos);
						//pos += 0x1000;
					}
					print_stack_pages_to_log(vcpu,file,5,rsp,&pos,buffer);
					if (split_tlb_procinfo(vcpu,buffer,PAGE_SIZE,&user_stack)) {
						kernel_write(file, buffer, PAGE_SIZE, &pos);
						if (user_stack!=0) {
							print_stack_pages_to_log(vcpu,file,5,user_stack,&pos,buffer);
						}
					}
				}
				filp_close(file,NULL);
			}
			kfree(buffer);
		}
		set_fs(old_fs); //Reset to save FS
	}
}

int split_tlb_flip_page(struct kvm_vcpu *vcpu, gpa_t gpa, struct kvm_splitpage* splitpage, unsigned long exit_qualification)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long cr3 = kvm_read_cr3(vcpu);
	unsigned long now_tick;
	phys_addr_t dataaddrphys = virt_to_phys(splitpage->dataaddr);
	phys_addr_t codeaddrphys = virt_to_phys(splitpage->codepage);
	if (dataaddrphys != splitpage->dataaddrphys) {
		printk(KERN_WARNING "split_tlb_flip_page: Data hpa changed from:0x%llx to:0x%llx\n",splitpage->dataaddrphys,dataaddrphys);
		splitpage->dataaddrphys = dataaddrphys;
	}	
	if (codeaddrphys != splitpage->codeaddr) {
		printk(KERN_WARNING "split_tlb_flip_page: Code hpa changed from:0x%llx to:0x%llx\n",splitpage->codeaddr,codeaddrphys);
		splitpage->codeaddr = codeaddrphys;
	}	

	/* --- LAZY EVICTION: Check if OS recycled the page BEFORE serving any access --- */
	if (splitpage->active) {
		u64 evaluated_pte = 0;
		bool page_recycled = false;

		if (splitpage->pte_gpa != 0 &&
		    !kvm_read_guest(vcpu->kvm, splitpage->pte_gpa, &evaluated_pte, sizeof(evaluated_pte))) {
			if (!(evaluated_pte & 1ULL) ||
			    (evaluated_pte & PT64_BASE_ADDR_MASK) != (splitpage->gpa & PT64_BASE_ADDR_MASK)) {
				page_recycled = true;
			}
		}

		if (page_recycled) {
			gpa_t old_gpa = 0;
			printk(KERN_INFO "split_tlb_flip_page: Physical page 0x%llx recycled by OS for gva 0x%lx. Suspending hook.\n", gpa, splitpage->gva);
			if (split_tlb_restore_spte(vcpu, gfn, splitpage) == 0)
				return 0;
			spin_lock(&vcpu->kvm->splitpages->track_lock);
			if (splitpage->gpa != 0) {
				old_gpa = splitpage->gpa;
				splitpage->gpa = 0;
			}
			spin_unlock(&vcpu->kvm->splitpages->track_lock);
			if (old_gpa != 0)
				split_tlb_allow_thp(vcpu->kvm, old_gpa);
			split_tlb_protect_pte(vcpu, splitpage, splitpage->pte_gpa);
			return 1; /* Hardware will retry and use the restored SPTE natively */
		}
	}

	if (!splitpage->active) {
		printk(KERN_INFO "split_tlb_flip_page: EPT fault on inactive page 0x%llx (GVA: 0x%lx). Returning 0 for KVM Native Page-In & Double-Fault!\n", gpa, splitpage->gva);
		return 0;
	}

	if (exit_qualification & PTE_WRITE) //write
	{
		printk(KERN_WARNING "split_tlb_flip_page: Malicious WRITE EPT fault at gpa 0x%llx (gva 0x%lx). detourpa:0x%llx rip:0x%lx vcpuid:%d Removing the page\n",gpa,splitpage->gva,dataaddrphys,rip,vcpu->vcpu_id);
		if (split_tlb_restore_spte(vcpu,gfn,splitpage)==0) {
			return 0;
		}
		kvm_split_tlb_freepage(vcpu->kvm, splitpage);
		printk(KERN_WARNING "split_tlb_flip_page: WRITE EPT fault at 0x%llx, page removed\n",gpa);
	} else if (exit_qualification & PTE_READ) //read
	{
		u64* sptep;
		log_read_flip(vcpu,rip);
		spin_lock(&vcpu->kvm->mmu_lock);
		sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
		if (exit_qualification & PTE_EXECUTE) //TODO handle execute&read, not sure if needed
			{
				printk(KERN_ERR "split_tlb_flip_page: read&execute EPT fault at gpa 0x%llx (gva 0x%lx). Need to handle it properly \n",gpa, splitpage->gva);
			}
		if (sptep!=NULL) {
			u64 newspte = *sptep;
			if (newspte==0) {
				splitpage->original_spte&=~PT64_BASE_ADDR_MASK; // using zero address as an indicator to later restore it to 0
				newspte = splitpage->original_spte;
				printk(KERN_WARNING "split_tlb_flip_page: found zero spte(READ) for gva 0x%lx: gpa:0x%llx/0x%llx, vm:%X\n",splitpage->gva, gpa,(u64)sptep,vcpu->kvm->splitpages->vmcounter);
			}
			if ((newspte&(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK|VMX_EPT_READABLE_MASK))==0) {
				printk(KERN_WARNING "split_tlb_flip_page: sptep last 3 bits are 0 for gpa:0x%llx (gva 0x%lx) vm:%x\n",gpa,splitpage->gva,vcpu->kvm->splitpages->vmcounter);
			}
			//splitpage->codeaddr = stepaddr;
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK);
			newspte|=VMX_EPT_READABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=dataaddrphys&PT64_BASE_ADDR_MASK;
			//printk(KERN_WARNING "split_tlb_flip_page: read EPT fault at 0x%llx/0x%llx -> 0x%llx detourpa:0x%llx rip:0x%lx\n vcpuid:%d\n",gpa,*sptep,newspte,detouraddr,rip,vcpu->vcpu_id);
			*sptep = newspte;
		} else {
			printk(KERN_ERR "split_tlb_flip_page: sptep not found for gpa 0x%llx (gva 0x%lx) \n",gpa, splitpage->gva);
			split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback_print);
			spin_unlock(&vcpu->kvm->mmu_lock);
			return 0;		
		}
		spin_unlock(&vcpu->kvm->mmu_lock);
		split_tlb_register_ept_flip(splitpage->gva, rip, cr3, vcpu->kvm, true);
		now_tick = jiffies;
		vcpu->split_pervcpu.exec_when_last_read = vcpu->split_pervcpu.last_exec_count;
		if ((rip == vcpu->split_pervcpu.last_read_rip) && (now_tick - vcpu->split_pervcpu.flip_tick) < HZ ) {
			vcpu->split_pervcpu.last_read_count++;
			vcpu->split_pervcpu.flip_tick = now_tick;
		} else {
			vcpu->split_pervcpu.last_read_rip = rip;
			vcpu->split_pervcpu.last_read_count = 0;
			vcpu->split_pervcpu.flip_tick = now_tick;
		}
	} else if (exit_qualification & PTE_EXECUTE) //execute
	{
		u64* sptep;
		spin_lock(&vcpu->kvm->mmu_lock);
		sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
		if (sptep!=NULL) {
			u64 newspte = *sptep;
			if (newspte==0) {
				splitpage->original_spte&=~PT64_BASE_ADDR_MASK; // using zero address as an indicator to later restore it to 0
				newspte = splitpage->original_spte;
				printk(KERN_WARNING "split_tlb_flip_page: found zero spte (EXEC) for gva 0x%lx: gpa:0x%llx/0x%llx, vm:%x\n",splitpage->gva,gpa,(u64)sptep,vcpu->kvm->splitpages->vmcounter);
			}
			if ((newspte&(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK|VMX_EPT_READABLE_MASK))==0) {
				printk(KERN_WARNING "split_tlb_flip_page: sptep last 3 bits are 0 for gpa:0x%llx (gva 0x%lx) vm:%x\n",gpa,splitpage->gva,vcpu->kvm->splitpages->vmcounter);
			}
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_READABLE_MASK);
			newspte|=VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=codeaddrphys&PT64_BASE_ADDR_MASK;
			//printk(KERN_WARNING "split_tlb_flip_page: execute EPT fault at 0x%llx/0x%llx -> 0x%llx detourpa:0x%llx rip:0x%lx\n vcpuid:%d\n",gpa,*sptep,newspte,detouraddr,rip,vcpu->vcpu_id);
			*sptep = newspte;
		} else {
			printk(KERN_ERR "split_tlb_flip_page: sptep not found for gpa 0x%llx (gva 0x%lx) \n",gpa, splitpage->gva);
			split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback_print);
			spin_unlock(&vcpu->kvm->mmu_lock);
			return 0;		
		}
		spin_unlock(&vcpu->kvm->mmu_lock);
		split_tlb_register_ept_flip(splitpage->gva, rip, cr3, vcpu->kvm, false);
		now_tick = jiffies;
		vcpu->split_pervcpu.read_when_last_exec = vcpu->split_pervcpu.last_read_count;
		if ( rip == vcpu->split_pervcpu.last_exec_rip && (now_tick - vcpu->split_pervcpu.flip_tick) < HZ) {
			vcpu->split_pervcpu.last_exec_count++;
			vcpu->split_pervcpu.flip_tick = now_tick;
		} else {
			vcpu->split_pervcpu.last_exec_rip = rip;
			vcpu->split_pervcpu.last_exec_count = 0;
			vcpu->split_pervcpu.flip_tick = now_tick;
		}
	} else
		printk(KERN_ERR "split_tlb_flip_page: unexpected EPT fault at gpa 0x%llx (gva 0x%lx) \n",gpa, splitpage->gva);
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_flip_page);

int deactivateAllPages(struct kvm_vcpu *vcpu) {
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	int i;

	if (!spages) {
		printk(KERN_WARNING "split_tlb: spages is NULL in deactivateAllPages!\n");
		return 0;
	}

	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
		gva_t gva = spages->pages[i].gva;
		gpa_t gpa = spages->pages[i].gpa;
		if (gva) {
			if (split_tlb_freepage_by_gpa(vcpu,gpa)==0) {
				printk(KERN_WARNING "deactivateAllPages: split_tlb_freepage failed for gva=%lx/gpa=%llx attempting to fix and free it based on saved gpa\n",gva,gpa);
				split_tlb_restore_spte(vcpu,gpa >> PAGE_SHIFT,spages->pages + i);
				kvm_split_tlb_freepage(vcpu->kvm, spages->pages + i);
			}
		}
	}
	split_tlb_setadjuster(vcpu,0,0,0);
	return 1;
}

int isPageSplit(struct kvm_vcpu *vcpu, gva_t addr, ulong cr3) {
	u32 access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	gpa_t addr_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, access, &exception);
	if (addr_gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "isPageSplit: address unmapped gva=%lx vm:%x\n",addr, vcpu->kvm->splitpages->vmcounter);
		return 0;
	}
	page = split_tlb_findpage_gva_cr3(vcpu->kvm, addr, cr3);
	if (page != NULL) {
		bool needs_healing = false;

		if (page->gpa != (addr_gpa & PAGE_MASK)) {
			printk(KERN_INFO "isPageSplit: auto-healing for GPA relocation gva=%lx (old gpa=0x%llx, new gpa=0x%llx, active=%d) vm:%x\n",
			       addr, page->gpa, addr_gpa & PAGE_MASK, page->active, vcpu->kvm->splitpages->vmcounter);
			needs_healing = true;
		} else {
			u64 *sptep;
			spin_lock(&vcpu->kvm->mmu_lock);
			sptep = split_tlb_findspte(vcpu, addr_gpa >> PAGE_SHIFT, split_tlb_findspte_callback);
			if (sptep) {
				u64 spte = split_tlb_safe_deref(sptep);
				/* Check if it's a native, fully permissive mapping. */
				if ((spte & (VMX_EPT_READABLE_MASK | VMX_EPT_WRITABLE_MASK | VMX_EPT_EXECUTABLE_MASK)) ==
				    (VMX_EPT_READABLE_MASK | VMX_EPT_WRITABLE_MASK | VMX_EPT_EXECUTABLE_MASK)) {
					printk(KERN_INFO "isPageSplit: auto-healing for bypassed EPT permissions on gva=%lx (native mapping found) vm:%x.\n", addr, vcpu->kvm->splitpages->vmcounter);
					needs_healing = true;
				}
			}
			spin_unlock(&vcpu->kvm->mmu_lock);
		}

		if (needs_healing)
			split_tlb_activatepage(vcpu, addr, cr3);
		return 1;
	} else {
		//printk(KERN_WARNING "isPageSplit: no split page for gva=%lx to gpa=0x%llx\n",addr,addr_gpa);
		return 0;
	}
}

unsigned long long split_tlb_safe_deref(unsigned long long * ptr) {
	unsigned long long result;
	int triggered = 0;
	asm volatile("xor %1,%1; \n\t"
		 "mov %2, %%rax; \n\t"
		 "1: mov (%%rax), %%rax; \n\t"
         "3: \n\t"
         ".pushsection .fixup, \"ax\"\n" 
		 "2: xor %%rax,%%rax \n\t"
		 "mov $0x1,%1 \n\t"
		 "jmp 3b \n\t"
         ".popsection\n"
   	     "mov %%rax, %0; \n\t"
   	     _ASM_EXTABLE(1b, 2b)
		 :"=rm"(result),"=rm"(triggered)        /* output */
		 :"rm"(ptr)         /* input */
		 :"%rax"         /* clobbered register */
		 );
		 if (triggered) {
			printk(KERN_WARNING "Page Fault triggered accessing %px\n",ptr);
		 }
	
	return result;
}

/*
 * rcx - opcode, rax will have magic word
 *
 * 0x0000: check if support is present
 *
 * 0x0001: Create split context
 * 		rbx - guest virtual address for page
 *
 * 0x0002: Activate page.
 * 		rbx - guest virtual address for page
 *
 * 0x0003: Deactivate page.
 * 		rbx - guest virtual address for page
 *
 * 0x0004: Deactivate all
 * 		return rcx = 1 - success
 * 		rcx = 0 - failure
 *
 * 0x0005: is page present
 * 		rbx - guest virtual address for data
 * 		return rcx = 1 - present
 * 		rcx = 0 - not present
 *
 * 0x0006: Write code for page. Only usable after page is active
 * 		rbx - guest virtual address for data
 * 		rsi - guest virtual address for destination
 * 		r8 - number of bytes
 *
 *
 *
 */

int split_tlb_vmcall_dispatch(struct kvm_vcpu *vcpu)
{
	unsigned long rip,cr3,rcx,rdx,rbx,rsi,r8;
	int result = 0;

	rip = kvm_rip_read(vcpu);
	cr3 = kvm_read_cr3(vcpu);
	rbx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	rdx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	rsi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	r8 = kvm_register_read(vcpu, VCPU_REGS_R8);
	//printk(KERN_DEBUG "VMCALL: rip:0x%lx cr3:0x%lx rcx:0x%lx rdx:0x%lx rsi:0x%lx r8:0x%lx\n",rip,cr3,rcx,rdx,rsi,r8);
	if (tlbsplit_magic != 0 && tlbsplit_magic != rdx) {
		return 0;
	}

	switch (rcx) {
		case 0x0000:
			result = 1;
			kvm_rax_write(vcpu, vcpu->kvm->splitpages->vmcounter);
			break;
		case 0x0001:
			result = split_tlb_setdatapage(vcpu,rbx,rbx,cr3);
			break;
		case 0x0002:
			result = split_tlb_activatepage(vcpu,rbx,cr3);
		        break;
		case 0x0003:
			result = split_tlb_freepage(vcpu,rbx);
			break;
		case 0x0004:
			result = deactivateAllPages(vcpu);
			break;
		case 0x0005:
			result = isPageSplit(vcpu,rbx,cr3);
			break;
		case 0x0006:
			result = split_tlb_copymem(vcpu,rbx,rsi,r8,cr3);
			break;
		case 0x1000:
			result = split_tlb_setadjuster(vcpu,rbx,rsi,r8);
			break;
		case 0x1001: {
				char buf[512];
				gva_t user_stack;
				result = split_tlb_procinfo(vcpu,buf,sizeof buf,&user_stack);
				printk(KERN_INFO "VMCALL: split_tlb_procinfo returned %s",buf);
			}
			break;
		case 0x1002: { // a test for additional thrashing bypass
			int emulate_result;
			unsigned long rip_after;
			kvm_skip_emulated_instruction(vcpu);  //skip VMCALL bytes
			rip = kvm_rip_read(vcpu);
			emulate_result = kvm_emulate_instruction(vcpu,0);
			rip_after = kvm_rip_read(vcpu);
			printk(KERN_INFO "VMCALL: rip b4:0x%lx after:0x%lx result:%d vm:%x\n",rip,rip_after,emulate_result, vcpu->kvm->splitpages->vmcounter);
			return 1;
			}
		break;
		case 0x1003: {
/*			struct x86_exception exception;
			u32 access = (kvm_x86_ops.get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
		    gpa_t from_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, rdx, access, &exception);	
		    kvm_register_write(vcpu, VCPU_REGS_RAX, from_gpa);*/
		    //u64 sptep = 12345;
		    printk(KERN_INFO "VMCALL: safe_deref 0x%lld vm:%x\n",split_tlb_safe_deref((unsigned long long *)123), vcpu->kvm->splitpages->vmcounter);
			}
			break;
		default:
			result = 0;
				printk(KERN_WARNING "VMCALL: invalid operation 0x%lx vm:%x\n",rcx, vcpu->kvm->splitpages->vmcounter);
	}
	kvm_register_write(vcpu, VCPU_REGS_RCX, result);
	//printk(KERN_INFO "VMCALL: rip before 0x%lx \n",kvm_rip_read(vcpu));
	kvm_skip_emulated_instruction(vcpu);
	//printk(KERN_INFO "VMCALL: rip after 0x%lx \n",kvm_rip_read(vcpu));
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_vmcall_dispatch);

int split_tlb_has_split_page(struct kvm *kvms, u64* sptep) {
	struct kvm_splitpage* found;
	int i;
	phys_addr_t pagehpa = *sptep & PT64_BASE_ADDR_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->active) {
			//phys_addr_t detouraddr = virt_to_phys(found->dataaddr);
			//printk(KERN_WARNING "split_tlb_has_split_page: comparing pagehpa:0x%llx with code/data hpa:0x%llx/0x%llx\n",pagehpa,found->codeaddr,found->dataaddrphys);
			if (pagehpa == found->codeaddr || pagehpa == found->dataaddrphys) {
				if (found->original_spte & PT64_BASE_ADDR_MASK)
				    *sptep = found->original_spte;
				else
				    *sptep = 0; //found->original_spte;
				printk(KERN_WARNING "split_tlb_has_split_page: found page gva:0x%lx VM:%x resetting to 0x%llx\n",found->gva,kvms->splitpages->vmcounter,*sptep);

				/* Force re-activation so we capture a potentially new Host PFN */
				found->active = false;
				//split_tlb_flip_to_code(kvms,found->codeaddr,sptep);
				return 1;
			}
		}
	}
	printk(KERN_WARNING "split_tlb_has_split_page: did not find split page spte:0x%llx\n",*sptep);
	return 0;
}

static void split_tlb_evaluate_hook(struct kvm_vcpu *vcpu, int i)
{
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	gva_t gva = spages->pages[i].gva;
	ulong cr3 = spages->pages[i].cr3;
	gpa_t pte_gpa;
	u64 evaluated_pte;
	u64 exact_gpa;
	gpa_t old_gpa = 0;

	if (gva == 0 || cr3 == 0)
		return;

	/* Proactively re-walk the hardware page tables to find the current physical mapping */
	pte_gpa = get_guest_pte_gpa(vcpu, cr3, gva);

	if (pte_gpa == 0 || kvm_read_guest(vcpu->kvm, pte_gpa, &evaluated_pte, sizeof(evaluated_pte)) || !(evaluated_pte & 1ULL)) {
		spin_lock(&spages->track_lock);
		if (spages->pages[i].active && spages->pages[i].gpa != 0) {
			old_gpa = spages->pages[i].gpa;
			spages->pages[i].gpa = 0;
		}
		spin_unlock(&spages->track_lock);
		if (old_gpa != 0) {
			printk(KERN_INFO "split_tlb: Hook for gva 0x%lx suspended via Flush (Unmapped).\n", gva);
			split_tlb_restore_spte(vcpu, old_gpa >> PAGE_SHIFT, &spages->pages[i]);
			split_tlb_allow_thp(vcpu->kvm, old_gpa);

			/* If we had a tripwire on the old page table, remove it since it's dead */
			if (spages->pages[i].pte_tracking_active)
				split_tlb_unprotect_pte(vcpu->kvm, &spages->pages[i]);
		}
		return;
	}

	/* The page is mapped in the OS. Calculate its exact physical address. */
	exact_gpa = evaluated_pte & PT64_BASE_ADDR_MASK;

	spin_lock(&spages->track_lock);
	if (spages->pages[i].active) {
		if (exact_gpa != spages->pages[i].gpa) {
			old_gpa = spages->pages[i].gpa;
			spages->pages[i].gpa = exact_gpa;
		}
	} else {
		spages->pages[i].gpa = exact_gpa;
		spages->pages[i].active = true;
		old_gpa = -1ULL;
	}
	spin_unlock(&spages->track_lock);

	if (old_gpa != 0 && old_gpa != -1ULL) {
		printk(KERN_INFO "split_tlb: Hook for gva 0x%lx relocated via Flush natively. Auto-healing to 0x%llx\n", gva, exact_gpa);
		split_tlb_allow_thp(vcpu->kvm, old_gpa);
		split_tlb_shatter_thp(vcpu, exact_gpa);
	} else if (old_gpa == -1ULL) {
		printk(KERN_INFO "split_tlb: Suspended hook for gva 0x%lx returned via Flush. Auto-healing to 0x%llx\n", gva, exact_gpa);
		split_tlb_shatter_thp(vcpu, exact_gpa);
	}

	/* Always ensure the EPT tripwire is locked onto the correct Page Table */
	if (pte_gpa != spages->pages[i].pte_gpa) {
		split_tlb_unprotect_pte(vcpu->kvm, &spages->pages[i]);
		split_tlb_protect_pte(vcpu, &spages->pages[i], pte_gpa);
	}
}

void split_tlb_invlpg(struct kvm_vcpu *vcpu, gva_t gva)
{
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	int i;

	if (!spages)
		return;

	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
		if (spages->pages[i].gva == (gva & PAGE_MASK))
			split_tlb_evaluate_hook(vcpu, i);
	}
}
EXPORT_SYMBOL_GPL(split_tlb_invlpg);

void split_tlb_flush_all(struct kvm_vcpu *vcpu)
{
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	int i;

	if (!spages)
		return;

	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
		if (spages->pages[i].gva != 0)
			split_tlb_evaluate_hook(vcpu, i);
	}
}
EXPORT_SYMBOL_GPL(split_tlb_flush_all);

int log_from_emulation = 0;
void tlbsplit_emulation_log(char* format, ...) {
	va_list args;
	if (log_from_emulation) {
		va_start(args, format);
		vprintk(format, args);
		va_end(args);
	}
}

int split_tlb_handle_mtf(struct kvm_vcpu *vcpu)
{
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	u64 evaluated_pte;
	int i;

	if (!vcpu->split_pervcpu.mtf_active)
		return 0; /* Not our MTF exit */

	vcpu->split_pervcpu.mtf_active = false;
	
	/* (VMX handler will clear the CPU_BASED_MONITOR_TRAP_FLAG before calling this) */

	if (vcpu->split_pervcpu.mtf_thrash_gpa) {
		gpa_t thrash_gpa = vcpu->split_pervcpu.mtf_thrash_gpa;
		struct kvm_splitpage* page;
		vcpu->split_pervcpu.mtf_thrash_gpa = 0;
		
		spin_lock(&vcpu->kvm->mmu_lock);
		page = split_tlb_findpage(vcpu->kvm, thrash_gpa);
		if (page && page->active) {
			u64* sptep = split_tlb_findspte(vcpu, thrash_gpa >> PAGE_SHIFT, split_tlb_findspte_callback);
			if (sptep) {
				u64 newspte = *sptep & ~(VMX_EPT_READABLE_MASK | VMX_EPT_WRITABLE_MASK | VMX_EPT_EXECUTABLE_MASK);
				newspte |= VMX_EPT_EXECUTABLE_MASK;
				newspte &= ~PT64_BASE_ADDR_MASK;
				newspte |= page->codeaddr & PT64_BASE_ADDR_MASK;
				*sptep = newspte;
				kvm_flush_remote_tlbs(vcpu->kvm);
			}
		}
		spin_unlock(&vcpu->kvm->mmu_lock);
		printk(KERN_INFO "split_tlb: MTF thrash bypass complete for GPA 0x%llx\n", thrash_gpa);
	}

	if (!spages)
		return 1;

	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
		if (spages->pages[i].pte_gpa != 0 && spages->pages[i].pte_gfn == vcpu->split_pervcpu.mtf_pte_gfn) {
			
			spages->pages[i].mtf_exits++;
			if ((spages->pages[i].mtf_exits % 1000000) == 0) {
				printk(KERN_INFO "split_tlb: %u MTF exits handled for PT at GPA 0x%llx\n", spages->pages[i].mtf_exits, spages->pages[i].pte_gpa);
			}
			
			/* 1. Check what the instruction actually did to the PTE */
			if (!kvm_read_guest(vcpu->kvm, spages->pages[i].pte_gpa, &evaluated_pte, sizeof(evaluated_pte))) {
				if (!(evaluated_pte & 1ULL /* PT_PRESENT_MASK */)) {
					gpa_t old_gpa = 0;
					/* 2. Still unmapped! Re-raise the EPT write-protection shield */
					split_tlb_protect_pte(vcpu, &spages->pages[i], spages->pages[i].pte_gpa);

					spin_lock(&spages->track_lock);
					if (spages->pages[i].active && spages->pages[i].gpa != 0) {
						old_gpa = spages->pages[i].gpa;
						spages->pages[i].gpa = 0;
					}
					spin_unlock(&spages->track_lock);

					if (old_gpa != 0) {
						printk(KERN_INFO "split_tlb: Hook for gva 0x%lx suspended (Page unmapped via MTF natively).\n", spages->pages[i].gva);
						split_tlb_restore_spte(vcpu, old_gpa >> PAGE_SHIFT, &spages->pages[i]);
						split_tlb_allow_thp(vcpu->kvm, old_gpa);
					}
				} else {
					u64 new_gpa = evaluated_pte & PT64_BASE_ADDR_MASK;
					bool was_active;
					gpa_t old_gpa = 0;
					
					spin_lock(&spages->track_lock);
					was_active = spages->pages[i].active;
					if (!was_active) {
						spages->pages[i].gpa = new_gpa;
						spages->pages[i].active = true;
					} else if (spages->pages[i].gpa != new_gpa) {
						old_gpa = spages->pages[i].gpa;
						spages->pages[i].gpa = new_gpa;
					}
					spin_unlock(&spages->track_lock);

					if (!was_active) {
						printk(KERN_INFO "split_tlb: Hook for gva 0x%lx reactivated at new GPA: 0x%llx via MTF\n", spages->pages[i].gva, new_gpa);
						split_tlb_shatter_thp(vcpu, new_gpa);
					} else if (old_gpa != 0) {
						printk(KERN_INFO "split_tlb: Hook for gva 0x%lx relocated to new GPA: 0x%llx via MTF natively\n", spages->pages[i].gva, new_gpa);
						split_tlb_allow_thp(vcpu->kvm, old_gpa);
						split_tlb_shatter_thp(vcpu, new_gpa);
					}
					
					/* The page is back in RAM. Drop the EPT shield for native performance! */
					split_tlb_unprotect_pte(vcpu->kvm, &spages->pages[i]);
				}
			} else {
				printk(KERN_ERR "split_tlb: MTF handler failed to read guest PTE for gva 0x%lx\n", spages->pages[i].gva);
			}
		}
	}
	
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_handle_mtf);

int split_tlb_handle_ept_violation(struct kvm_vcpu *vcpu,gpa_t gpa,unsigned long exit_qualification,int* splitresult) {
	static int emulate_mode = 0xFFFF;
	struct kvm_splitpage* splitpage;
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	int i;

	*splitresult = 1;

	/* MTF ENTRY POINT: Did the hardware trap on our protected Guest Page Table? */
	if (spages) {
		bool mtf_armed = false;
		for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
			if (spages->pages[i].pte_tracking_active &&
			    spages->pages[i].pte_gpa != 0 &&
			    (gpa >> PAGE_SHIFT) == spages->pages[i].pte_gfn) {
				
				/* 
				 * We caught a write to the protected Page Table!
				 * KVM's emulator cannot handle complex Windows MM instructions (like AVX).
				 * We drop the EPT write-protection, flag MTF, and let the hardware execute it natively.
				 */

				if (!mtf_armed) {
					//printk_ratelimited(KERN_INFO "split_tlb: EPT write to PT detected at 0x%llx. Unprotecting & arming MTF.\n", gpa);

					/* 1. Arm our internal MTF state first */
					vcpu->split_pervcpu.mtf_active = true;
					vcpu->split_pervcpu.mtf_pte_gfn = spages->pages[i].pte_gfn;
					mtf_armed = true;
				}
				
				/* 2. Temporarily drop the EPT write protection for EVERY overlapping hook */
				split_tlb_unprotect_pte(vcpu->kvm, &spages->pages[i]);
			}
		}
		if (mtf_armed)
			/* The fault is handled. Let the guest re-execute the instruction. */
			return 1;
	}

	splitpage = split_tlb_findpage(vcpu->kvm,gpa);
	if (splitpage!=NULL) {
		int exec_when_last_read = vcpu->split_pervcpu.exec_when_last_read;
		int read_when_last_exec = vcpu->split_pervcpu.read_when_last_exec;
		//printk(KERN_DEBUG "handle_ept_violation on split page: 0x%llx exitqualification:%lx\n",gpa,exit_qualification);
		if (split_tlb_flip_page(vcpu,gpa,splitpage,exit_qualification)){
			bool emulate_now = 0;
			bool exit_on_same_addr = vcpu->split_pervcpu.last_read_rip == vcpu->split_pervcpu.last_exec_rip;
			int thrashed = 0; 
			if (exit_on_same_addr) 
			   thrashed =  vcpu->split_pervcpu.last_read_count + vcpu->split_pervcpu.last_exec_count;
			/*else {
				if (exit_qualification & PTE_READ) {
					thrashed += vcpu->split_pervcpu.last_read_count;
				}
				if (exit_qualification & PTE_EXECUTE) {
					thrashed += vcpu->split_pervcpu.last_exec_count;
				}
			}*/
			if ( thrashed >= 4 ) {
				/*if ( thrashed == 4 ) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: thrashing detected at r0x%lx/x0x%lx qualification: 0x%lx",vcpu->split_pervcpu.last_read_rip,vcpu->split_pervcpu.last_exec_rip,exit_qualification);
				//	kvm_flush_remote_tlbs(vcpu->kvm);
				}*/
				if (exit_qualification & PTE_READ) {
					if ( ( exec_when_last_read == vcpu->split_pervcpu.last_exec_count ) || exit_on_same_addr ) 
						emulate_now = 1;
					/*else
					    printk(KERN_INFO "split_tlb_handle_ept_violation: not emulating because last_exec_count went from %d to %d",exec_when_last_read,vcpu->split_pervcpu.last_exec_count);*/
				}
				if (exit_qualification & PTE_EXECUTE) {
					if ( ( read_when_last_exec == vcpu->split_pervcpu.last_read_count ) || exit_on_same_addr) 
						emulate_now = 1;
					/*else
					    printk(KERN_INFO "split_tlb_handle_ept_violation: not emulating because last_read_count went from %d to %d",read_when_last_exec,vcpu->split_pervcpu.last_read_count);*/
				}
			}
			if (tlbsplit_emulate_on_violation || emulate_now) {
				unsigned long rip_before = kvm_rip_read(vcpu);
				int er;
				if (emulate_mode!=0xFFFF && emulate_mode!=tlbsplit_emulate_on_violation) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: emulation mode changed to true");
				}
				emulate_mode = tlbsplit_emulate_on_violation;
				//er = kvm_emulate_instruction(vcpu,0);
				//log_from_emulation = 1;
				er = kvm_emulate_instruction(vcpu,0);
				//log_from_emulation = 0;
				if (er == 1 && rip_before != kvm_rip_read(vcpu)) {
					vcpu->split_pervcpu.last_exec_count = 0;
					vcpu->split_pervcpu.last_read_count = 0;
				} else {
					printk(KERN_WARNING "handle_ept_violation: emulation stuck/failed er:%d rip:0x%lx gpa:0x%llx. Stepping over natively via MTF!\n", er, rip_before, gpa);
					spin_lock(&vcpu->kvm->mmu_lock);
					splitpage = split_tlb_findpage(vcpu->kvm, gpa);
					if (splitpage) {
						u64* sptep = split_tlb_findspte(vcpu, gpa >> PAGE_SHIFT, split_tlb_findspte_callback);
						if (sptep) {
							u64 newspte = *sptep & ~(VMX_EPT_READABLE_MASK | VMX_EPT_WRITABLE_MASK | VMX_EPT_EXECUTABLE_MASK);
							newspte |= VMX_EPT_READABLE_MASK | VMX_EPT_EXECUTABLE_MASK;
							newspte &= ~PT64_BASE_ADDR_MASK;
							newspte |= splitpage->dataaddrphys & PT64_BASE_ADDR_MASK;
							*sptep = newspte;
							kvm_flush_remote_tlbs(vcpu->kvm);
							
							vcpu->split_pervcpu.mtf_thrash_gpa = splitpage->gpa;
							vcpu->split_pervcpu.mtf_active = true;
						}
					}
					spin_unlock(&vcpu->kvm->mmu_lock);
					*splitresult = 1;
				}
			} else {
				*splitresult = 1;
				if (emulate_mode!=0xFFFF && emulate_mode!=tlbsplit_emulate_on_violation) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: emulation mode changed to false");
				}
				emulate_mode = tlbsplit_emulate_on_violation;
			}

		} else {
			printk(KERN_WARNING "handle_ept_violation split_tlb_flip_page returned 0 page: 0x%llx (GVA: 0x%lx)\n", gpa, splitpage->gva);
			return 0;
		}
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(split_tlb_handle_ept_violation);

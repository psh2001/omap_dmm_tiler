/*
 * drivers/gpu/ion/omap_tiler_heap.c
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/spinlock.h>

#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/ion.h>
#include <linux/mm.h>
#include <linux/omap_ion.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
//#include <mach/tiler.h>
#include "../../../drivers/staging/omapdrm/omap_dmm_tiler.h"
#include <asm/mach/map.h>
#include <asm/page.h>

#include "../ion_priv.h"

typedef struct tiler_block *tiler_handle_t;

static int omap_tiler_heap_allocate(struct ion_heap *heap,
				    struct ion_buffer *buffer,
				    unsigned long size, unsigned long align,
				    unsigned long flags)
{
	if (size == 0)
		return 0;

	pr_err("%s: This should never be called directly -- use the "
	       "OMAP_ION_TILER_ALLOC flag to the ION_IOC_CUSTOM "
	       "instead\n", __func__);
	return -EINVAL;
}

struct omap_tiler_info {
	tiler_handle_t tiler_handle;	        /* handle of the allocation intiler */
	bool lump;			/* true for a single lump allocation */
	u32 n_phys_pages;		/* number of physical pages */
	u32 *phys_addrs;		/* array addrs of pages */
	u32 n_tiler_pages;		/* number of tiler pages */
	u32 *tiler_addrs;		/* array of addrs of tiler pages */
	u32 tiler_start;		/* start addr in tiler -- if not page
					   aligned this may not equal the
					   first entry onf tiler_addrs */
	u32 phys;
};
#if 0
static const struct {
        uint32_t x_shft;        /* unused X-bits (as part of bpp) */
        uint32_t y_shft;        /* unused Y-bits (as part of bpp) */
        uint32_t cpp;           /* bytes/chars per pixel */
        uint32_t slot_w;        /* width of each slot (in pixels) */
        uint32_t slot_h;        /* height of each slot (in pixels) */
} geom[TILFMT_NFORMATS] = {
                [TILFMT_8BIT]  = GEOM(0, 0, 1),
                [TILFMT_16BIT] = GEOM(0, 1, 2),
                [TILFMT_32BIT] = GEOM(1, 1, 4),
                [TILFMT_PAGE]  = GEOM(SLOT_WIDTH_BITS, SLOT_HEIGHT_BITS, 1),
};
#endif

#define TILER_FMT(x)    ((enum tiler_fmt) \
                ((x >> SHIFT_ACC_MODE) & MASK_ACC_MODE))

enum tiler_fmt tiler_fmt(u32 phys)
{
        return TILER_FMT(phys);
}

static u32 tiler_block_vstride( u32 phy)
{
	struct omap_ion_tiler_alloc_data *data;	
	printk("+++++++++value of params: w=%d h=%d fmt=%d\n", data->w, data->h, data->fmt);
        return PAGE_ALIGN((phy & ~PAGE_MASK) + geom[data->fmt].cpp * data->w);
}

u32 tiler_pstride(u32 phys)
{
        enum tiler_fmt fmt = tiler_fmt(phys);
    //    BUG_ON(fmt == TILFMT_INVALID);

        /* return the virtual stride for page mode */
        if (fmt == TILFMT_PAGE)
                return tiler_block_vstride(phys);

        return tiler_stride(phys & ~MASK_VIEW);
}

s32 tiler_fill_virt_array(u32 phys, u32 *virt_array,
                u32 *array_size)
{
        u32 v, p, len, size, num_pages = 0;
        u32 i = 0, offs = 0;
        struct omap_ion_tiler_alloc_data *data;

        if (!array_size)
                return -1;

        /* get page aligned stride */
        v = tiler_block_vstride(phys);
        p = tiler_pstride(phys);

        /* get page aligned virtual size for the block */
        size = PAGE_ALIGN(tiler_size(data->fmt, data->w, data->h));

        if (*array_size < (size/PAGE_SIZE) || !virt_array) {
                *array_size = (size/PAGE_SIZE);
                return -2;
        }

        offs = (phys & PAGE_MASK);
        while (size) {
                /* set len to length of one row (2D), or full length if 1D */
                len = v;

                while (len && size) {
                        virt_array[i++] = offs;
                        num_pages++;
                        size -= PAGE_SIZE;
                        len -= PAGE_SIZE;
                        offs += PAGE_SIZE;
                }

                /* set offset to next row beginning */
                offs += p - v;
        }

        *array_size = num_pages;

        return 0;
}

int omap_tiler_alloc(struct ion_heap *heap,
		     struct ion_client *client,
		     struct omap_ion_tiler_alloc_data *data)
{
	struct ion_handle *handle;
	struct ion_buffer *buffer;
	struct omap_tiler_info *info;
	tiler_handle_t tiler_handle;
	u32 n_phys_pages;
	u32 n_tiler_pages;
	ion_phys_addr_t addr;
	int i, ret;
	size_t size;
	//u16 aln;
	struct page **pages;

	if (data->fmt == TILER_PIXEL_FMT_PAGE && data->h != 1) {
		pr_err("%s: Page mode (1D) allocations must have a height "
		       "of one\n", __func__);
		return -EINVAL;
	}
#if 0
	ret = tiler_memsize(data->fmt, data->w, data->h,
			    &n_phys_pages,
			    &n_tiler_pages);

	if (ret) {
		pr_err("%s: invalid tiler request w %u h %u fmt %u\n", __func__,
		       data->w, data->h, data->fmt);
		return ret;
	}

	BUG_ON(!n_phys_pages || !n_tiler_pages);
#endif /* ics obsolete */
	printk("+++++++++value of params: w=%d h=%d fmt=%d\n", data->w, data->h, data->fmt);
	tiler_handle = tiler_reserve_2d(data->fmt, data->w, data->h, 4096);
	printk("+++++++++++tiler_handle allocated=%x\n", tiler_handle);

	if (IS_ERR_OR_NULL(tiler_handle)) {
		ret = PTR_ERR(tiler_handle);
		pr_err("%s: failure to allocate address space from tiler\n",
			__func__);
		goto err_nomem;
	}
	size = tiler_vsize(data->fmt, data->w, data->h);
	n_tiler_pages = size / PAGE_SIZE;

	info = kzalloc(sizeof(struct omap_tiler_info) +
		       sizeof(u32) * n_phys_pages +
		       sizeof(u32) * n_tiler_pages, GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	info->tiler_handle = tiler_handle;
	info->n_phys_pages = n_phys_pages;
	info->n_tiler_pages = n_tiler_pages;
	info->phys_addrs = (u32 *)(info + 1);
	info->tiler_addrs = info->phys_addrs + n_phys_pages;

	if (IS_ERR_OR_NULL(info->tiler_handle)) {
		ret = PTR_ERR(tiler_handle);
		pr_err("%s: failure to allocate address space from tiler\n",
		       __func__);
		goto err_nomem;
	}

	addr = ion_carveout_allocate(heap, n_phys_pages*PAGE_SIZE, 0);
	if (addr == ION_CARVEOUT_ALLOCATE_FAIL) {
		for (i = 0; i < n_phys_pages; i++) {
			addr = ion_carveout_allocate(heap, PAGE_SIZE, 0);

			if (addr == ION_CARVEOUT_ALLOCATE_FAIL) {
				ret = -ENOMEM;
				pr_err("%s: failed to allocate pages to back "
					"tiler address space\n", __func__);
				goto err_alloc;
			}
			info->phys_addrs[i] = addr;
		}
	} else {
		info->lump = true;
		for (i = 0; i < n_phys_pages; i++)
			info->phys_addrs[i] = addr + i*PAGE_SIZE;
	}

	ret = tiler_pin(tiler_handle, pages, info->n_phys_pages, 0, true);
			      
	if (ret) {
		pr_err("%s: failure to pin pages to tiler\n", __func__);
		goto err_alloc;
	}
#if 0
static inline u32 tiler_vstride(const struct tiler_block_t *b)
{
        return PAGE_ALIGN((b->phys & ~PAGE_MASK) + tiler_bpp(b) * b->width);
}
#endif

	info->phys = tiler_ssptr(tiler_handle);
	data->stride = tiler_block_vstride(info->phys);

	/* create an ion handle  for the allocation */
	handle = ion_alloc(client, 0, 0, 1 << OMAP_ION_HEAP_TILER);
	if (IS_ERR_OR_NULL(handle)) {
		ret = PTR_ERR(handle);
		pr_err("%s: failure to allocate handle to manage tiler"
		       " allocation\n", __func__);
		goto err;
	}

	buffer = ion_handle_buffer(handle);
	buffer->size = size * PAGE_SIZE;
	buffer->priv_virt = info;
	data->handle = handle;

	if (tiler_fill_virt_array(info->phys, info->tiler_addrs,
                        &n_tiler_pages) < 0) {
                pr_err("%s: failure filling tiler's virtual array %d\n",
                                __func__, n_tiler_pages);
        }
	return 0;

err:
	tiler_unpin(tiler_handle);
err_alloc:
	tiler_release(tiler_handle);
	if (info->lump)
		ion_carveout_free(heap, addr, n_phys_pages * PAGE_SIZE);
	else
		for (i -= 1; i >= 0; i--)
			ion_carveout_free(heap, info->phys_addrs[i], PAGE_SIZE);
err_nomem:
	kfree(info);
	return ret;
}

#if 0
s32 tiler_fill_virt_array(u32 phys, u32 *virt_array,
                u32 *array_size)
{
        u32 v, p, len, size, num_pages = 0;
        u32 i = 0, offs = 0;
	struct omap_ion_tiler_alloc_data *data;

        if (!array_size)
                return -1;

        /* get page aligned stride */
        v = tiler_block_vstride(phys);
        p = tiler_pstride(phys);

        /* get page aligned virtual size for the block */
        size = PAGE_ALIGN(tiler_size(data->fmt, data->w, data->h));

        if (*array_size < (size/PAGE_SIZE) || !virt_array) {
                *array_size = (size/PAGE_SIZE);
                return -2;
        }

        offs = (phys & PAGE_MASK);
        while (size) {
                /* set len to length of one row (2D), or full length if 1D */
                len = v;

                while (len && size) {
                        virt_array[i++] = offs;
                        num_pages++;
                        size -= PAGE_SIZE;
                        len -= PAGE_SIZE;
                        offs += PAGE_SIZE;
                }

                /* set offset to next row beginning */
                offs += p - v;
        }

        *array_size = num_pages;

        return 0;
}
#endif

void omap_tiler_heap_free(struct ion_buffer *buffer)
{
	struct omap_tiler_info *info = buffer->priv_virt;

	tiler_unpin(info->tiler_handle);
	tiler_release(info->tiler_handle);

	if (info->lump) {
		ion_carveout_free(buffer->heap, info->phys_addrs[0],
				  info->n_phys_pages*PAGE_SIZE);
	} else {
		int i;
		for (i = 0; i < info->n_phys_pages; i++)
			ion_carveout_free(buffer->heap,
					  info->phys_addrs[i], PAGE_SIZE);
	}

	kfree(info);
}

static int omap_tiler_phys(struct ion_heap *heap,
			   struct ion_buffer *buffer,
			   ion_phys_addr_t *addr, size_t *len)
{
	struct omap_tiler_info *info = buffer->priv_virt;

	*addr = info->tiler_start;
	*len = buffer->size;
	return 0;
}

int omap_tiler_pages(struct ion_client *client, struct ion_handle *handle,
		     int *n, u32 **tiler_addrs)
{
	ion_phys_addr_t addr;
	size_t len;
	int ret;
	struct omap_tiler_info *info = ion_handle_buffer(handle)->priv_virt;

	/* validate that the handle exists in this client */
	ret = ion_phys(client, handle, &addr, &len);
	if (ret)
		return ret;

	*n = info->n_tiler_pages;
	*tiler_addrs = info->tiler_addrs;
	return 0;
}

int omap_tiler_heap_map_user(struct ion_heap *heap, struct ion_buffer *buffer,
			     struct vm_area_struct *vma)
{
	struct omap_tiler_info *info = buffer->priv_virt;
	unsigned long addr = vma->vm_start;
	u32 vma_pages = (vma->vm_end - vma->vm_start) / PAGE_SIZE;
	int n_pages = min(vma_pages, info->n_tiler_pages);
	int i, ret;

	for (i = vma->vm_pgoff; i < n_pages; i++, addr += PAGE_SIZE) {
		ret = remap_pfn_range(vma, addr,
				      __phys_to_pfn(info->tiler_addrs[i]),
				      PAGE_SIZE,
				      pgprot_noncached(vma->vm_page_prot));
		if (ret)
			return ret;
	}
	return 0;
}

static struct ion_heap_ops omap_tiler_ops = {
	.allocate = omap_tiler_heap_allocate,
	.free = omap_tiler_heap_free,
	.phys = omap_tiler_phys,
	.map_user = omap_tiler_heap_map_user,
};

struct ion_heap *omap_tiler_heap_create(struct ion_platform_heap *data)
{
	struct ion_heap *heap;

	heap = ion_carveout_heap_create(data);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->ops = &omap_tiler_ops;
	heap->type = OMAP_ION_HEAP_TYPE_TILER;
	heap->name = data->name;
	heap->id = data->id;
	return heap;
}

void omap_tiler_heap_destroy(struct ion_heap *heap)
{
	kfree(heap);
}

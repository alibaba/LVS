/*
 * Functions related to generic helpers functions
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>

#include "blk.h"

static void blkdev_discard_end_io(struct bio *bio, int err)
{
	if (err) {
		if (err == -EOPNOTSUPP)
			set_bit(BIO_EOPNOTSUPP, &bio->bi_flags);
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	}

	if (bio->bi_private)
		complete(bio->bi_private);

	bio_put(bio);
}

/**
 * blkdev_issue_discard - queue a discard
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	BLKDEV_IFL_* flags to control behaviour
 *
 * Description:
 *    Issue a discard request for the sectors in question.
 */
int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, int flags)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	struct request_queue *q = bdev_get_queue(bdev);
	int type = (1 << BIO_RW) | (1 << BIO_RW_DISCARD);
	unsigned int max_discard_sectors;
	struct bio *bio;
	int ret = 0;

	/*
	 * DEPRECATED support for DISCARD_FL_BARRIER which will
	 * fail with -EOPNOTSUPP (due to implicit BIO_RW_BARRIER)
	 */
	if (flags & DISCARD_FL_BARRIER)
		type = DISCARD_BARRIER;

	if (!q)
		return -ENXIO;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	/*
	 * Ensure that max_discard_sectors is of the proper
	 * granularity
	 */
	max_discard_sectors = min(q->limits.max_discard_sectors, UINT_MAX >> 9);
	if (unlikely(!max_discard_sectors)) {
		/* Avoid infinite loop below. Being cautious never hurts. */
		return -EOPNOTSUPP;
	} else if (q->limits.discard_granularity) {
		unsigned int disc_sects = q->limits.discard_granularity >> 9;

		max_discard_sectors &= ~(disc_sects - 1);
	}

	while (nr_sects && !ret) {
		bio = bio_alloc(gfp_mask, 1);
		if (!bio) {
			ret = -ENOMEM;
			break;
		}

		bio->bi_sector = sector;
		bio->bi_end_io = blkdev_discard_end_io;
		bio->bi_bdev = bdev;
		bio->bi_private = &wait;

		if (nr_sects > max_discard_sectors) {
			bio->bi_size = max_discard_sectors << 9;
			nr_sects -= max_discard_sectors;
			sector += max_discard_sectors;
		} else {
			bio->bi_size = nr_sects << 9;
			nr_sects = 0;
		}

		bio_get(bio);
		submit_bio(type, bio);

		wait_for_completion(&wait);

		if (bio_flagged(bio, BIO_EOPNOTSUPP))
			ret = -EOPNOTSUPP;
		else if (!bio_flagged(bio, BIO_UPTODATE))
			ret = -EIO;
		bio_put(bio);
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_discard);

<?php

global $thisstaff, $ticket, $spamblockMeta;

$canMarkSpam = false;
if ($ticket && $thisstaff) {
    $canMarkSpam = $thisstaff->hasPerm(Email::PERM_BANLIST)
        && $ticket->checkStaffPerm($thisstaff, Ticket::PERM_DELETE);
}

$email = $spamblockMeta ? (string) $spamblockMeta['email'] : '';
$isSpam = $spamblockMeta ? (bool) $spamblockMeta['is_spam'] : false;
$postmarkScore = $spamblockMeta ? $spamblockMeta['postmark_score'] : null;
$sfsConfidence = $spamblockMeta ? $spamblockMeta['sfs_confidence'] : null;

?>
<div style="padding: 10px 12px;">
    <h3 style="margin: 0 0 10px;">
        <?php echo __('Spamblock'); ?>
    </h3>

    <div style="margin: 0 0 10px;">
        <strong><?php echo __('Is Spam?'); ?></strong>
        <?php echo $isSpam ? __('Yes') : __('No'); ?>
    </div>

    <table class="table" style="margin: 0 0 10px;">
        <thead>
            <tr>
                <th><?php echo __('System'); ?></th>
                <th><?php echo __('Score'); ?></th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><?php echo __('Spamcheck'); ?></td>
                <td><?php echo ($postmarkScore !== null) ? (string) $postmarkScore : __('n/a'); ?></td>
            </tr>
            <tr>
                <td><?php echo __('SFS'); ?></td>
                <td><?php echo ($sfsConfidence !== null) ? (string) $sfsConfidence : __('n/a'); ?></td>
            </tr>
        </tbody>
    </table>

    <?php if ($canMarkSpam) { ?>
        <form id="spamblock-mark-spam" method="post" action="ajax.php/spamblock/ticket/<?php echo $ticket->getId(); ?>/mark-spam">
            <?php csrf_token(); ?>
            <button type="submit" class="button danger"><?php echo __('This is spam'); ?></button>
            <span class="faded" style="margin-left: 8px;">
                <?php echo sprintf(__('Will ban %s and delete this ticket.'), Format::htmlchars($email ?: __('(no email)'))); ?>
            </span>
        </form>
    <?php } else { ?>
        <div class="faded">
            <?php echo __('You do not have permission to ban email and delete tickets.'); ?>
        </div>
    <?php } ?>
</div>

<script>
$(function() {
    var $form = $('#spamblock-mark-spam');
    if (!$form.length)
        return;

    $form.on('submit', function(e) {
        e.preventDefault();

        if (!confirm(<?php echo JsonDataEncoder::encode(__('Ban email and delete this ticket?')); ?>))
            return;

        $.ajax({
            url: $form.attr('action'),
            method: 'POST',
            data: $form.serialize(),
            success: function() {
                window.location = 'tickets.php';
            },
            error: function(xhr) {
                alert(xhr && xhr.responseText ? xhr.responseText : 'Request failed');
            }
        });
    });
});
</script>

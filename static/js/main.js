$(function () {
    $('.need-confirm').click(function (e) {
        //get href of click
        var href = $(this).attr('href');
        $("#dialog-confirm").dialog({
            resizable: false,
            height: 180,
            modal: true,
            buttons: {
                OK: function () {
                    $(this).dialog("close");
                    //redirect manually ONLY on success.
                    window.location = href;
                },
                Cancel: function () {
                    $(this).dialog("close");
                }
            }
        });
        //always cancel the click.
        e.preventDefault();
    })
});
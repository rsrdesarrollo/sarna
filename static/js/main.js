function ask_confirmation() {
    return new Promise(function (resolve, reject) {
        $("#dialog-confirm").dialog({
            resizable: false,
            height: 180,
            modal: true,
            buttons: {
                OK: function () {
                    $(this).dialog("close");
                    resolve();
                },
                Cancel: function () {
                    $(this).dialog("close");
                    reject();
                }
            }
        });
    });
}

$(function () {
    var confirmed = false;
    $('.need-confirm').click(function (e) {
        var elem = $(this);
        var href = elem.attr('href');

        if (confirmed) {
            confirmed = false;
            if(href){
                window.location.href = href;
            }
            return;
        }
        e.preventDefault();
        ask_confirmation().then(
            function () {
                confirmed = true;
                elem.trigger('click')
            }
        );

    });

    $(".clickable-row").click(function () {
        window.location = $(this).data("href");
    });

    $(".datepicker").datepicker({
        dateFormat: "yy-mm-dd"
    });

    $('#all_checked').click(function () {
        var is_checked = $(this).prop("checked");
        $('#table_data tr:has(td)').find('input[type="checkbox"]').prop('checked', is_checked);
    });

    $('#table_data tr:has(td)').find('input[type="checkbox"]').click(function () {
        var is_checked = $(this).prop("checked");
        var is_header_checked = $("#all_checked").prop("checked");
        if (is_checked == false && is_header_checked)
            $("#all_checked").prop('checked', is_checked);
        else {
            $('#table_data tr:has(td)').find('input[type="checkbox"]').each(function () {
                if ($(this).prop("checked") == false)
                    is_checked = false;
            });
            $("#all_checked").prop('checked', is_checked);
        }
    });
});
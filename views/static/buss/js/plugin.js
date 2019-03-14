$('.dropify').dropify({
    messages: {
        'default': 'Drag and drop a file here or click',
        'replace': 'Drag and drop or click to replace',
        'remove': 'Remove',
        'error': 'Ooops, something wrong appended.'
    },
    error: {
        'fileSize': 'The file size is too big (1M max).'
    }
});

$('#field-type').change(function () {
    if ($(this).val() == 'json') {
        $('.uploadjson').css('display', '');
        $('.uploadfile').css('display', 'none');
    } else if ($(this).val() == 'script') {
        $('.uploadjson').css('display', 'none');
        $('.uploadfile').css('display', '');
    } else {
        $('.uploadjson').css('display', 'none');
        $('.uploadfile').css('display', 'none');
    }
});

$('#add').click(function () {
    name = $('#field-name').val();
    info = $('#field-info').val();
    author = $('#field-author').val();
    level = $('#field-risk').val();
    vultype = $('#field-new-vultype').val() == '' ? $('#field-vultype').val() : $('#field-new-vultype').val();
    type = $('#field-vultype').val();
    methodurl = $('#field-url').val();
    pdata = $('#field-data').val();
    analyzing = $('#field-analyzing').val();
    analyzingdata = $('#field-analyzingdata').val();
    tag = $('#field-tag').val();
    condition = $('#field-condition').val();
    pluginurl = $('#field-pluginurl').val();
    path = $('#field-upload').val();
    filename = path.substring(path.lastIndexOf('\\')).split('.')[0];
    isupload = $('#field-isupload').val();
    $.ajaxFileUpload({
        url: "/addplugin",
        secureuri: false,
        type: "POST",
        data: {
            name: name,
            info: info,
            author: author,
            level: level,
            vultype: vultype,
            type: type,
            methodurl: methodurl,
            pdata: pdata,
            analyzing: analyzing,
            analyzingdata: analyzingdata,
            tag: tag,
            keyword: condition,
            pluginurl: pluginurl,
            isupload: isupload,
            upload_csrf_token: csrf_token
        },
        dataType: "json",
        fileElementId: "field-upload",
        success: function (e) {
        },
        error: function (e) {
            if (e.responseText == 'success') {
                swal("新增成功", '', "success");
                $('.confirm').click(function () {
                    $('#close').click();
                    location.reload();
                });

            } else {
                swal("新增失败", "请检查数据是否完整或是否存在特殊字符!", "error")
            }
        }
    });

});

$('.zmdi-close').click(function () {
    var oid = $(this).attr('id');
    swal({
            title: "确认删除？",
            text: "所有删除操作将不可逆，请谨慎操作",
            type: "warning",
            showCancelButton: true,
            confirmButtonColor: "#DD6B55",
            confirmButtonText: "确定",
            cancelButtonText: "取消",
            closeOnConfirm: false
        },
        function () {
            $.post('/deleteplugin', {oid: oid}, function (e) {
                if (e == 'success') {
                    swal("已删除", '', "success");
                    $('#' + oid).parent().parent().parent().parent().remove()
                }
                else {
                    swal("删除失败", '', "error");
                }
            })

        });
});
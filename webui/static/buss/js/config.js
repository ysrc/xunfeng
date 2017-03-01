$('.update').click(function () {
    name = $(this).attr('inputname');
    value = $(document.getElementsByName($(this).attr('inputname'))).val();
    if (name == "Masscan") {
        value = $("#speed").val() + "|" + value;
    }
    $.post('/updateconfig', {
        name: name,
        value: value,
        conftype: location.search.replace('?', '').split('&')[0].split('=')[1]
    }, function (data) {
        if (data == 'success') {
            swal("更新成功", '', "success");
        }
        else {
            swal("更新失败", '请检查数据完整性', "error");
        }
    })
});

$('#mastag').change(function () {
    var name = "Masscan_Flag";
    var conftype = "nascan";
    var value = $(this).is(':checked') == true ? "1" : "0";
    $.post('/updateconfig', {name: name, value: value, conftype: conftype}, function (data) {
        if (data == "patherr") {
            $("#mastag").click();
            swal("切换失败", '未检测到Masscan，请先安装或先配置正确的路径', "error");
        }
        else if (data == "fail") {
            swal("切换失败", '请检查数据完整性', "error");
        }
    })
});


$('#icmptag').change(function () {
    var name = "Port_list_Flag";
    var conftype = "nascan";
    var value = $(this).is(':checked') == true ? "1" : "0";
    $.post('/updateconfig', {name: name, value: value, conftype: conftype}, function (data) {
        if (data !== 'success') {
            swal("更新失败", '请检查数据完整性', "error");
        }
    })
});

$('.zmdi-help-outline').poshytip({
    className: 'tip-twitter',
    showTimeout: 1,
    alignTo: 'target',
    alignX: 'center',
    alignY: 'bottom',
    offsetY: 5,
    allowTipHover: false,
    fade: false,
    slide: false
});
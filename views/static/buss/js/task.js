function getQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
    var r = window.location.search.substr(1).match(reg);
    if (r != null) return unescape(r[2]);
    return null;
}

$('.tag').click(function () {
    if ($(this).hasClass('zmdi-plus')) {
        $(this).removeClass('zmdi-plus').addClass('zmdi-minus')
    } else if ($(this).hasClass('zmdi-minus')) {
        $(this).removeClass('zmdi-minus').addClass('zmdi-plus')
    }
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
            $.post('/deletetask', {oid: oid}, function (e) {
                if (e == 'success') {
                    swal("已删除", '', "success");
                    $('#' + oid).parent().parent().parent().parent().parent().remove()
                }
                else {
                    swal("删除失败", '', "error");
                }
            })

        });
});

$('.deleteall').click(function () {
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
            $.post('/deleteall', function (e) {
                if (e == 'success') {
                    swal("已删除", '', "success");
                    $('.confirm').click(function () {
                        location.href = "/task";
                    })
                }
                else {
                    swal("删除失败", '', "error");
                    $('.confirm').click(function () {
                        location.href = "/task";
                    })
                }

            })

        });
});

$('.recheck').click(function () {
    taskid = $(this).parents('h4').children().first().attr('href').split('=')[1];
    swal({
            title: "复测该任务",
            text: "立即重新执行该任务（历史数据不会删除）",
            type: "info",
            showCancelButton: true,
            closeOnConfirm: false,
            showLoaderOnConfirm: true
        },
        function () {
            $.get('/taskrecheck', {taskid: taskid}, function (e) {
                if (e == 'success') {
                    swal("操作成功", "该任务将重新执行!", "success")
                } else {
                    swal("操作失败", "该任务非可复测类型，要求已经完成的非计划型任务", "error")
                }
            })
        });
});


function tasknextPage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) + 1;
    if (page > $('.pagination-split').children().length - 2) {
        alert('已到达末页');
    } else {
        oripage = page - 1;
        if (getQueryString('page') == null) {
            location.href = location.href + "?page=" + page.toString();
        } else {
            location.href = location.href.replace("?page=" + oripage.toString(), "?page=" + page.toString());
        }
    }
}
function taskprePage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) - 1;
    if (page > 0) {
        location.href = '/task?page=' + page;
    }
    else {
        alert('已到达首页');
    }
}

function taskturnTo(page) {
    curPage = getQueryString('page');
    if (curPage != null) {
        url = location.href.replace("?page=" + getQueryString('page'), "?page=" + page);
        location.href = url
    } else {
        url = location.href + "?page=" + page;
        location.href = url
    }
}
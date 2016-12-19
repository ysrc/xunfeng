function getQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
    var r = window.location.search.substr(1).match(reg);
    if (r != null) return unescape(r[2]);
    return null;
}


jQuery('#datepicker').datepicker({
    format: "mm/dd/yyyy",
    clearBtn: true,
    multidate: true,
    multidateSeparator: ","
});
jQuery('#date-range').datepicker({
    toggleActive: true
});
function nextPage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) + 1;
    location.href = '/taskdetail?taskid=' + getQueryString('taskid') + "&page=" + page;
}
function prePage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) - 1;
    if (page > 0) {
        location.href = '/taskdetail?taskid=' + getQueryString('taskid') + "&page=" + page;
    } else {
        alert('已到达首页');
    }
}

$('.taglink').click(function () {
    $(this).attr('href', "/taskdetail?taskid=" + getQueryString('taskid') + "&taskdate=" + $(this).attr('title'))

});
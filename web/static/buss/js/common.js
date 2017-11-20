
function getQueryString(name) {
    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)", "i");
    var r = window.location.search.substr(1).match(reg);
    if (r != null) return unescape(r[2]);
    return null;
}

function setCookie(c_name, value, expirehours) {
    var exdate = new Date();
    exdate.setHours(exdate.getHours() + expirehours);
    document.cookie = c_name + "=" + escape(value) +
        ((expirehours == null) ? "" : ";expires=" + exdate.toGMTString())
}

function getCookie(name) {
    var cookies = document.cookie.split(";");
    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i];
        var cookieStr = cookie.split("=");
        if (cookieStr && cookieStr[0].trim() == name) {
            return decodeURI(cookieStr[1]);
        }
    }
}


function delAllCookie() {
    var myDate = new Date();
    myDate.setTime(-1000);
    var data = document.cookie;
    var dataArray = data.split("; ");
    for (var i = 0; i < dataArray.length; i++) {
        var varName = dataArray[i].split("=");
        document.cookie = varName[0] + "=''; expires=" + myDate.toGMTString();
    }

}

/**
 * 更新url中的get请求
 *
 * @param    {string}  key     http get query key
 * @param    {string}  key     http get query value
 * @returns  url?key=value&key=value
 */
String.prototype.url_update_query = function(key, value) {
    if (key) {
        var re = new RegExp("([?&])" + key + "=.*?(&|$)", "i");
        var separator = this.indexOf('?') !== -1 ? "&" : "?";
        if (this.match(re)) {
            return this.replace(re, '$1' + key + "=" + value + '$2');
        }
        else {
            return this + separator + key + "=" + value;
        }
    }
    return this.toString();
}

/**
 * 更新url中的page参数
 *
 * @param    {string}  page    the number of page
 * @returns  url?page=1
 *
 * @author   ysrc
 */
String.prototype.url_add_Paginator = function(page) {
    if (page == undefined) {
        return this.toString();
    } 
    result = this.url_update_query("page", page);
    return result.toString();
}

/**
 * 跳转到下一页
 *
 * @author   ysrc
 */
function nextPage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) + 1;
    if (page > $('.pagination-split').children().length - 2) {
        alert('已到达末页');
    } else {
        location.replace(location.href.url_add_Paginator(page));
    }
}

function prePage() {
    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page')) - 1;
    if (page > 0) {
        oripage = page + 1;
        location.href = location.href.replace("page=" + oripage.toString(), "page=" + page.toString());
    } else {
        alert('已到达首页');
    }
}
function turnTo(page) {
    curPage = getQueryString('page');
    location.replace(location.href.url_add_Paginator(page));
}

function getplugininfo(e) {
    var that = $(e.target).parents('a');
    var unicode = $(that).attr('unicode');
    var name = $(that).children('.user-desc').children('.name').text();
    var desc = $(that).children('.user-desc').children('.desc').text();
    var author = $(that).children('.user-desc').children('.author').attr('title');
    swal({
            title: "插件安装确认",
            text: "插件名：" + name + "\n描述：" + desc + "\n作者：" + author,
            type: "info",
            showCancelButton: true,
            closeOnConfirm: false,
            showLoaderOnConfirm: true
        },
        function () {
            $.get('/installplugin', {unicode: unicode}, function (e) {
                if (e == "success") {
                    justCheck();
                    swal("安装成功");
                } else {
                    swal("安装失败，一定是姿势不对");
                }
            });
        });
}


function firstpull() {
    $.get('/pullupdate', function () {
        justCheck()
    })
}

function justCheck() {
    $.getJSON('/checkupdate', function (data) {
        if (data.length > 0) {
            delAllCookie();
            $('.user-list').html("");
            setCookie('plugins', encodeURI(JSON.stringify(data)), 1);
            $('.noti-dot').css('display', 'block');
            $.each(data, function (i, item) {
                $('.user-list').append("<li class='list-group-item'>\
                            <a href='javascript:void(0)' class='user-list-item' unicode='" + item['unicode'] + "'>\
                                <div class='user-desc'>\
                                    <span class='name' title='" + item['name'] + "'>" + item['name'] + "</span>\
                                    <span class='desc' title='" + item['info'] + "'>" + item['info'] + "</span>\
                                    <span class='author' title='" + item['author'] + "'>author：" + item['author'] + "</span>\
                                    <span class='time'>" + item['time'] + "</span>\
                                </div></a></li>")
            });
        } else {
            setCookie('plugins', '', 1);
        }
    })
}


$(document).ready(function () {
    $(".list-group").delegate("a", "click", function (e) {
        getplugininfo(e)
    });
    if (document.cookie == '') {
        firstpull();
    } else {
        var plugins = getCookie('plugins');
        if (plugins != '') {
            var json = JSON.parse(decodeURI(plugins).replace(/%3A/g, ':').replace(/%2C/g, ','));
            if (json.length > 0) {
                $('.noti-dot').css('display', 'block');
                $.each(json, function (i, item) {
                    $('.user-list').append("<li class='list-group-item'>\
                        <a href='javascript:void(0)' class='user-list-item' unicode='" + item['unicode'] + "'>\
                            <div class='user-desc'>\
                                <span class='name' title='" + item['name'] + "'>" + item['name'] + "</span>\
                                <span class='desc' title='" + item['info'] + "'>" + item['info'] + "</span>\
                                <span class='author' title='" + item['author'] + "'>author：" + item['author'] + "</span>\
                                <span class='time'>" + item['time'] + "</span>\
                            </div></a></li>")
                });
            }
        }
    }


    page = parseInt(getQueryString('page') == null ? 1 : getQueryString('page'));
    item = $('.pagination-split').children()[page];
    if (item != undefined) {
        $(item).addClass('active');
    }
    length = $('.pagination-split').children().length;
    if (length > 7) {
        $.each($('.pagination-split').children(), function (e) {
            $(this).css('display', 'none');
        });
        $($('.pagination-split').children()[0]).css('display', '');
        $($('.pagination-split').children()[length - 1]).css('display', '');
        $($('.pagination-split').children()[1]).css('display', '');
        $($('.pagination-split').children()[length - 2]).css('display', '');
        $($('.pagination-split').children()[page - 1]).css('display', '');
        $($('.pagination-split').children()[page]).css('display', '');
        $($('.pagination-split').children()[page + 1]).css('display', '');
        if (page < 6) {
            for (i = 1; i < 6; i++) {
                $($('.pagination-split').children()[i]).css('display', '');
            }
            $($('.pagination-split').children()[length - 2]).before("<li><a href='javascript:void(0)'>...</a></li>")
        }
        else if (page > length - 6) {
            for (i = length - 6; i < length - 1; i++) {
                $($('.pagination-split').children()[i]).css('display', '');
            }
            $($('.pagination-split').children()[1]).after("<li><a href='javascript:void(0)'>...</a></li>")
        }
        else {
            $($('.pagination-split').children()[length - 2]).before("<li><a href='javascript:void(0)'>...</a></li>")
            $($('.pagination-split').children()[1]).after("<li><a href='javascript:void(0)'>...</a></li>")
        }

    }
});

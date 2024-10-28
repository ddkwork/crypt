current_timestamp = function () {//获取当前时间戳
    let date = new Date();
    let now = date.getTime() / 1000
    return parseInt(now)
}

function date_to_timestamp(current_date) {//日期转时间戳
    return Date.parse(current_date) / 1000
}

function timestamp_to_date(timestamp) {//时间戳转日期
    timestamp = timestamp + '000'
    date = new Date(parseInt(timestamp))
    Y = date.getFullYear() + '-'
    M = (date.getMonth() + 1 < 10 ? '0' + (date.getMonth() + 1) : date.getMonth() + 1) + '-'
    D = date.getDate() < 10 ? '0' + (date.getDate()) + ' ' : date.getDate() + ' '
    h = (date.getHours() < 10 ? '0' + (date.getHours()) : date.getHours()) + ':'
    m = (date.getMinutes() < 10 ? '0' + (date.getMinutes()) : date.getMinutes()) + ':'
    s = date.getSeconds() < 10 ? '0' + (date.getSeconds()) : date.getSeconds()
    return current_date = Y + M + D + h + m + s
}

// console.log(current_timestamp());
// console.log(date_to_timestamp("2021-10-20 18:00:25"));
// console.log(timestamp_to_date(1634724025));
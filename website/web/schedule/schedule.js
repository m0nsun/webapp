var date = new Date();

function renderCalendar() {
    date.setDate(1);

    var monthDays = document.querySelector(".days");

    var lastDay = new Date(
        date.getFullYear(),
        date.getMonth() + 1,
        0
    ).getDate();

    var prevLastDay = new Date(
        date.getFullYear(),
        date.getMonth(),
        0
    ).getDate();

    var firstDayIndex = date.getDay();

    var lastDayIndex = new Date(
        date.getFullYear(),
        date.getMonth() + 1,
        0
    ).getDay();

    var nextDays = 7 - lastDayIndex - 1;

    const months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];

    document.querySelector(".date h1").innerHTML = months[date.getMonth()]+"   "+date.getFullYear().toString();

    document.querySelector(".date p").innerHTML = new Date().toDateString();

    let days = "";

    for (let x = firstDayIndex; x > 0; x--) {
        days += `<div id="notToday" class="prev-date">${prevLastDay - x + 1}</div>`;
    }

    for (let i = 1; i <= lastDay; i++) {
         if (
            i === new Date().getDate() &&
            date.getMonth() === new Date().getMonth()
        ) {
            days += `<div id="todayid" class="today">${i}</div>`;
        } else {
            days += `<div id="notToday">${i}</div>`;
        }
    }

    if (nextDays > 0) {
        for (let j = 1; j <= nextDays; j++) {
            days += `<div id="notToday" class="next-date">${j}</div>`;
            monthDays.innerHTML = days;
        }
    } else {
        monthDays.innerHTML = days;
    }


   /* for (let j = 1; j <= nextDays; j++) {
        days += `<div id="notToday" class="next-date">${j}</div>`;
        monthDays.innerHTML = days;
    }*/

}

document.querySelector(".prev").addEventListener("click", () => {
    date.setMonth(date.getMonth() - 1);
    renderCalendar();
});

document.querySelector(".next").addEventListener("click", () => {
    date.setMonth(date.getMonth() + 1);
    renderCalendar();
});
renderCalendar();
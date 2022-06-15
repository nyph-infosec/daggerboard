$('#sbomSummary').DataTable();

var firstCrit = document.getElementById('firstCrit').innerText;
var firstHigh = document.getElementById('firstHigh').innerText;
var firstMed = document.getElementById('firstMed').innerText;
var firstLow = document.getElementById('firstLow').innerText;

//Chart js For demo purposes
var xValues1 = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
var yValues1 = [firstLow, firstMed, firstHigh, firstCrit];
var barColors = ["#739174", "#4D5C74", "#d1964d", "#a85556"];

new Chart("recent-sbom-chart-1", {
    type: "bar",
    data: {
        labels: xValues1,
        datasets: [{
            backgroundColor: barColors,
            data: yValues1,
            label: "",
            minBarLength: 1,
        }]
    },
    options: {
        scales: {
            x: {
                beginAtZero: true,
            },
            y: {
                min: 0,
                ticks: {
                    stepSize: 1,
                }
            },
        },
        plugins: {
            legend: {
                display: false
            },
            title: {
                display: false,
                text: ""
            }
        },
    }
});


var secondCrit = document.getElementById('secondCrit').innerText;
var secondHigh = document.getElementById('secondHigh').innerText;
var secondMed = document.getElementById('secondMed').innerText;
var secondLow = document.getElementById('secondLow').innerText;

var xValues2 = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
var yValues2 = [secondLow, secondMed, secondHigh, secondCrit];
console.log(yValues2);

new Chart("recent-sbom-chart-2", {
    type: "bar",
    data: {
        labels: xValues2,
        datasets: [{
            backgroundColor: barColors,
            data: yValues2,
            label: "",
            minBarLength: 1,
        }]
    },
    options: {
        scales: {
            x: {
                beginAtZero: true,
            },
            y: {
                min: 0,
                ticks: {
                    stepSize: 1,
                }
            },
        },
        plugins: {
            legend: {
                display: false
            },
            title: {
                display: false,
                text: ""
            }
        },
    }
});

$(document).ready(function () {
    $('#sbomSummary').DataTable();
});
$(document).on("change", "#select_vendor",function(){
    this.form.submit()
});

// SBOM history table
var xValuesMonth = [];
var yValuesTotals = [];


var history_table_contents = JSON.parse(document.getElementById('sbom_history_table').innerText);

for (let val = 0; val < history_table_contents.length; val++) {
    xValuesMonth.push(history_table_contents[val].month + " "+ history_table_contents[val].year);
    yValuesTotals.push(history_table_contents[val].count);
  }

var barColors = ["#a85556", "#d1964d", "#4D5C74", "#739174"];

var ctx1 = document.getElementById("sbom-history-chart").getContext("2d");
var sbom_hist_chart = new Chart(ctx1, {
    type: "line",
    data: {
        labels: xValuesMonth,
        datasets: [{
            backgroundColor: barColors,
            data: yValuesTotals,
        }]
    },
    options: {
        scales: {
            x: {
                beginAtZero: true
            },
            y: {
                min: 0,
                ticks: {
                    stepSize: 1
                }
            },
        },
        plugins: {
            legend: {display: false},
            title: {
                display: false,
            }
        }
    }
});


//vendor severity distribution
var xValuesSeverity1 = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
var yData1 = JSON.parse(document.getElementById('vendor_severity_dist').innerText);


var ctx2 = document.getElementById("vendor_severity_dist_chart").getContext("2d");
var vendor_sc_chart = new Chart(ctx2, {
    type: "bar",
    data: {
        labels: xValuesSeverity1,
        datasets: [{
            backgroundColor: barColors,
            data: yData1
        }]
    },
    options: {
        plugins: {
            legend: {display: false},
            title: {
                display: true,
                text: ""
            }
        }
    }
});

var xValuesSeverity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
var yDataSeverity = JSON.parse(document.getElementById('most_recent_sbom').innerText);

var ctx3 = document.getElementById("recent-sbom-chart").getContext("2d");
var vendor_recent_chart = new Chart(ctx3, {
    type: "bar",
    data: {
        labels: xValuesSeverity,
        datasets: [{
            backgroundColor: barColors,
            data: yDataSeverity
        }]
    },
    options: {
        plugins: {
            legend: {display: false},
            title: {
                display: true,
                text: ""
            }
        }
    }
});


// datatable
$(document).ready(function () {
    $('#sbomSummary').DataTable();
});


var ss = new SlimSelect({
    select: '#select_vendor',
});

sbom_hist_chart.destroy()
vendor_sc_chart.destroy()
vendor_recent_chart.destroy()
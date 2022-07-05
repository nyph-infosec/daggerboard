// SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
//
// SPDX-License-Identifier: MIT

$(document).on("change", "#select_sbom",function(){
    this.form.submit()
});

var ss = new SlimSelect({
    select: '#select_sbom',
});


//cvss vector chart
var yData1 = JSON.parse(document.getElementById('spider_vals').innerText);
var yData2 = JSON.parse(document.getElementById('severity_values_y').innerText);

// Generate JS charts if data is available
if (yData1.length > 0 || yData2.length > 0){
    genSpider(yData1);
    genBar(yData2);
} else {
    console.log("No chart data received.");
}

function genSpider(spider_data) {
    var cvss_spider = document.getElementById("sbom_cvss_vector_chart");
    new Chart(cvss_spider, {
        type: "radar",
        data: {
            labels: ["Remote Exploit", "Local Exploit", "Physical Exploit", "Impacts Confidentiality", "Impacts Integrity", "Impacts Availability"],
            datasets: [{
                backgroundColor: "#a85556",
                data: spider_data,
                label: "",

            }]
        },
        options: {
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
}

function genBar(bar_data) {
//SBOM severity distribution
    var barColors = ["#a85556", "#d1964d", "#4D5C74", "#739174"];
    var xValuesSeverity2 = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    var sbom_severity_dist = document.getElementById("severity_dist_chart");
    new Chart(sbom_severity_dist, {
        type: "bar",
        data: {
            labels: xValuesSeverity2,
            datasets: [{
                backgroundColor: barColors,
                data: bar_data,
            }]
        },
        options: {
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: false,
                    text: ""
                }
            },
            responsive: true,
            scale: {
                ticks: {
                    display: false
                }
            },
        }
    });
}

// package details datatable
$(document).ready(function () {
    $('#packageDetails').DataTable();
    // vulnerability details datatable
    $('#vulnerabilityDetails').DataTable();
});

//Package and vulnerability navtab switcher
document.body.addEventListener('click', function (e) {
    if (e.target.className === 'nav-link') {
        console.log("navlink selected");
    }
    //$(".nav-item .nav-link").on("click", function(){
});
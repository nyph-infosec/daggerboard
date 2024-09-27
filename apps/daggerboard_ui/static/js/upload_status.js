// SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
//
// SPDX-License-Identifier: MIT

$(document).ready(function () {
    let thost = window.location.host;
    let tproto = window.location.protocol;
    update_progress(tproto, thost);
});

function update_progress(proto, host) {
    //const status_url = new URL(proto + host + "/uploadstatus");
    const status_url = new URL(proto + host + "/sbomuploadstatus");
    console.log(status_url)
    // send GET request to status URL
    try {
        $.getJSON(status_url, function (data) {
            if (Object.keys(data).length === 0) {
                // if not an array or JSON is empty
                return false;
            } else if (!data["process_status"]) {
                return false;
            } else if (data["process_status"]) {
                // update UI
                for (let key in data["active_jobs"]) {
                    let value = data["active_jobs"][key];
                    let job_id_val = JSON.stringify(key);
                    let li_item = document.getElementById(key);
                    if (value["status_code"] > 1 || value["status"] === "failed" || value["status"] === "cancelled" || value["status"] === "invalid" || value["status"] === "stopped") {
                        //if upload error
                        if (li_item) {
                            li_item.classList.remove('list-group-item-success');
                            li_item.classList.remove('list-group-item-primary');
                            li_item.classList.add('list-group-item-danger');
                            li_item.innerHTML = '<div class="d-flex align-items-center"><div class="me-3"><i class="far fa-times-circle"></i></div><div><div class="text-truncate text-truncate text-wrap small">' + value["filename"] + '</div><div class="small text-muted text-truncate text-wrap" id="upload-sbom-body"><span class="text-truncate text-wrap fw-bold">' + value["status"] + "</span> " + value["error_code"] + '</div></div></div>';

                        } else {
                            let err_progress_li = '<li class="list-group-item list-group-item-danger" id=' + job_id_val + '><div class="d-flex align-items-center"><div class="me-3"><i class="far fa-times-circle"></i></div><div><div class="text-truncate text-truncate text-wrap small">' + value["filename"] + '</div><div class="small text-muted text-truncate text-wrap" id="upload-sbom-body"><span class="text-truncate text-wrap fw-bold">' + value["status"] + " </span>" + value["error_code"] + '</div></div></div></li>';
                            document.querySelector(".active-upload-status").insertAdjacentHTML('beforeend', err_progress_li);
                        }
                    } else if (value["status"] === "finished") {
                        if (li_item) {
                            li_item.classList.remove('list-group-item-danger');
                            li_item.classList.remove('list-group-item-primary');
                            li_item.classList.add('list-group-item-success');
                            li_item.innerHTML = '<div class="d-flex align-items-center"><div class="me-3"><i class="far fa-times-circle"></i></div><div><div class="text-truncate text-truncate text-wrap small">' + value["filename"] + '</div><div class="small text-muted text-truncate text-wrap" id="upload-sbom-body"><span class="text-truncate text-wrap fw-bold">' + value["status"] + " </span>" + value["error_code"] + '</div></div></div>';
                        } else {
                            let success_progress_li = '<li class="list-group-item list-group-item-success" id=' + job_id_val + '><div class="d-flex align-items-center" id="' + data["active_jobs"][key] + '"><div class="me-3"><i class="far fa-check-circle"></i></div><div><div class="text-truncate text-truncate text-wrap small">' + value["filename"] + '</div><div class="small text-muted text-truncate text-wrap" id="upload-sbom-body"><span class="text-truncate text-wrap fw-bold">' + value["status"] + '</span></div></div></div></li>';
                            document.querySelector(".active-upload-status").insertAdjacentHTML('beforeend', success_progress_li);
                        }
                    } else {
                        if (li_item) {
                            li_item.classList.remove('list-group-item-success');
                            li_item.classList.add('list-group-item-primary');
                            li_item.innerHTML = '<div class="d-flex align-items-center"><div class="me-3"><div class="spinner-border spinner-border-sm" role="status"></div></div><div><div class="text-truncate text-truncate text-wrap small">' + value["filename"] + '</div><div class="small text-muted text-truncate text-wrap" id="upload-sbom-body"><span class="text-truncate text-wrap fw-bold">' + value["status"] + '</span></div></div></div>';
                        } else {
                            let upload_progress_li = '<li class="list-group-item list-group-item-success" id=' + job_id_val + '><div class="d-flex align-items-center"><div class="me-3"><div class="spinner-border spinner-border-sm" role="status"></div></div><div><div class="text-truncate text-truncate text-wrap small">' + value["filename"] + '</div><div class="small text-muted text-truncate text-wrap" id="upload-sbom-body"><span class="text-truncate text-wrap fw-bold">' + value["status"] + '</span></div></div></div></li>';
                            document.querySelector(".active-upload-status").insertAdjacentHTML('beforeend', upload_progress_li);
                        }
                    }
                }
                setTimeout(function () {
                    update_progress(proto, host);
                }, 1000);
            }
        });
    } catch (error) {
        console.log(error);
    }
}

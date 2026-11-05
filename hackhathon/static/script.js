document.addEventListener("DOMContentLoaded", function () {

    // Get HTML elements
    const fileTab = document.getElementById("fileTab");
    const urlTab = document.getElementById("urlTab");

    const fileSection = document.getElementById("fileSection");
    const urlSection = document.getElementById("urlSection");

    const fileInput = document.getElementById("fileInput");
    const browseBtn = document.getElementById("browseBtn");

    const uploadBox = document.getElementById("uploadBox");
    const selectedFile = document.getElementById("selectedFile");

    const scanFileBtn = document.getElementById("scanFileBtn");
    const scanUrlBtn = document.getElementById("scanUrlBtn");

    const loading = document.getElementById("loading");
    const results = document.getElementById("results");

    // Check whether HTML elements exist
    if (
        !fileTab || !urlTab ||
        !fileSection || !urlSection ||
        !fileInput || !browseBtn ||
        !uploadBox || !scanFileBtn ||
        !scanUrlBtn || !loading || !results
    ) {
        console.error("SafeFile: Required HTML elements are missing.");
        return;
    }


    // --------------------------------
    // 1. SWITCH BETWEEN TABS
    // --------------------------------

    fileTab.addEventListener("click", function () {

        fileTab.classList.add("active");
        urlTab.classList.remove("active");

        fileSection.classList.remove("hidden");
        urlSection.classList.add("hidden");

        hideResults();

    });


    urlTab.addEventListener("click", function () {

        urlTab.classList.add("active");
        fileTab.classList.remove("active");

        urlSection.classList.remove("hidden");
        fileSection.classList.add("hidden");

        hideResults();

    });


    // --------------------------------
    // 2. OPEN FILE PICKER
    // --------------------------------

    browseBtn.addEventListener("click", function (event) {

        event.preventDefault();
        event.stopPropagation();

        fileInput.click();

    });


    // Click anywhere in upload area
    uploadBox.addEventListener("click", function (event) {

        if (event.target.closest("button")) {
            return;
        }

        fileInput.click();

    });


    // --------------------------------
    // 3. DISPLAY SELECTED FILE
    // --------------------------------

    fileInput.addEventListener("change", function () {

        const file = fileInput.files[0];

        if (file) {

            selectedFile.textContent =
                "Selected File: " + file.name;

            hideResults();

        }

    });


    // --------------------------------
    // 4. DRAG AND DROP
    // --------------------------------

    uploadBox.addEventListener("dragover", function (event) {

        event.preventDefault();

        uploadBox.style.borderColor = "#39d9a6";

    });


    uploadBox.addEventListener("dragleave", function () {

        uploadBox.style.borderColor = "#34465f";

    });


    uploadBox.addEventListener("drop", function (event) {

        event.preventDefault();

        uploadBox.style.borderColor = "#34465f";

        const files = event.dataTransfer.files;

        if (files.length > 0) {

            fileInput.files = files;

            selectedFile.textContent =
                "Selected File: " + files[0].name;

            hideResults();

        }

    });


    // --------------------------------
    // 5. FILE SCANNING
    // --------------------------------

    scanFileBtn.addEventListener("click", async function () {

        const file = fileInput.files[0];

        if (!file) {

            alert("Please select a file first.");

            return;

        }


        if (file.size > 20 * 1024 * 1024) {

            alert("File must be smaller than 20 MB.");

            return;

        }


        const formData = new FormData();

        formData.append("file", file);

        showLoading();

        try {

            const response = await fetch("/api/scan-file", {

                method: "POST",

                body: formData

            });


            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "File scanning failed."
                );

            }

            displayResults(data, "file");

        }

        catch (error) {

            console.error("File scanning error:", error);

            alert(error.message);

            hideLoading();

        }

    });


    // --------------------------------
    // 6. URL SCANNING
    // --------------------------------

    scanUrlBtn.addEventListener("click", async function () {

        const urlInput = document.getElementById("urlInput");

        const url = urlInput.value.trim();

        if (!url) {

            alert("Please enter a website URL.");

            return;

        }

        showLoading();

        try {

            const response = await fetch("/api/scan-url", {

                method: "POST",

                headers: {

                    "Content-Type": "application/json"

                },

                body: JSON.stringify({

                    url: url

                })

            });


            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.error || "URL scanning failed."
                );

            }

            displayResults(data, "url");

        }

        catch (error) {

            console.error("URL scanning error:", error);

            alert(error.message);

            hideLoading();

        }

    });


    // --------------------------------
    // 7. DISPLAY RESULTS
    // --------------------------------

    function displayResults(data, type) {

        hideLoading();

        results.classList.remove("hidden");

        document.getElementById("riskScore").textContent =
            data.risk_score;

        document.getElementById("riskStatus").textContent =
            data.status;

        document.getElementById("resultDescription").textContent =
            "Analysis completed. Review the security findings below.";


        // Risk score color

        const scoreCircle =
            document.getElementById("scoreCircle");

        if (data.risk_score >= 60) {

            scoreCircle.style.borderColor = "#ff5364";

        }

        else if (data.risk_score >= 25) {

            scoreCircle.style.borderColor = "#ffbd4a";

        }

        else {

            scoreCircle.style.borderColor = "#39d9a6";

        }


        // File or URL information

        document.getElementById("targetName").textContent =
            type === "file" ? data.filename : data.url;

        document.getElementById("hashValue").textContent =
            data.sha256 || "Not applicable";

        document.getElementById("fileSize").textContent =
            data.file_size !== undefined
                ? (data.file_size / 1024).toFixed(2) + " KB"
                : "Not applicable";


        // --------------------------------
        // SECURITY FINDINGS
        // --------------------------------

        const findingsList =
            document.getElementById("findingsList");

        findingsList.replaceChildren();

        if (!data.findings || data.findings.length === 0) {

            const message = document.createElement("p");

            message.className = "no-findings";

            message.textContent =
                "No suspicious indicators detected by the current checks.";

            findingsList.appendChild(message);

        }

        else {

            data.findings.forEach(function (finding) {

                const box = document.createElement("div");

                box.className =
                    "finding " + finding.severity;

                const title = document.createElement("h4");

                title.textContent = finding.title;

                const description = document.createElement("p");

                description.textContent = finding.description;

                box.appendChild(title);

                box.appendChild(description);

                findingsList.appendChild(box);

            });

        }


        // --------------------------------
        // VIRUSTOTAL REPORT
        // --------------------------------

        const vtReport =
            document.getElementById("vtReport");

        vtReport.replaceChildren();

        const vt = data.virustotal;

        const vtBox = document.createElement("div");

        vtBox.className = "vt-box";


        if (!vt) {

            vtBox.textContent =
                "VirusTotal is not configured. Local analysis completed.";

        }

        else if (vt.error) {

            vtBox.textContent =
                vt.error + " Local analysis is still available.";

        }

        else {

            vtBox.textContent =
                "Malicious: " + vt.malicious +
                " | Suspicious: " + vt.suspicious +
                " | Harmless: " + vt.harmless +
                " | Undetected: " + vt.undetected;

        }


        vtReport.appendChild(vtBox);


        // Scroll to report

        results.scrollIntoView({

            behavior: "smooth",

            block: "start"

        });

    }


    // --------------------------------
    // 8. LOADING SCREEN
    // --------------------------------

    function showLoading() {

        results.classList.add("hidden");

        loading.classList.remove("hidden");

        scanFileBtn.disabled = true;

        scanUrlBtn.disabled = true;

    }


    function hideLoading() {

        loading.classList.add("hidden");

        scanFileBtn.disabled = false;

        scanUrlBtn.disabled = false;

    }


    // --------------------------------
    // 9. HIDE RESULTS
    // --------------------------------

    function hideResults() {

        results.classList.add("hidden");

    }


    console.log("SafeFile Pro JavaScript loaded successfully!");

});
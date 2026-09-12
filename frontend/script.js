/* ============================================================
   PhishLens Frontend
   Complete Dashboard Script
   ============================================================ */

const API_URL = "http://127.0.0.1:8000";

let selectedFile = null;


/* ============================================================
   DOM ELEMENTS
   ============================================================ */

const fileInput =
    document.getElementById("fileInput");

const browseButton =
    document.getElementById("browseButton");

const uploadArea =
    document.getElementById("dropZone");

const selectedFileElement =
    document.getElementById("selectedFile");

const analyzeButton =
    document.getElementById("analyzeButton");

const resetButton =
    document.getElementById("resetButton");

const loadingState =
    document.getElementById("loadingSection");

const resultsSection =
    document.getElementById("resultsSection");

const errorMessage =
    document.getElementById("errorMessage");

const apiStatus =
    document.getElementById("statusText");


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        checkAPIStatus();

        setupFileUpload();

        setupButtons();

    }
);


/* ============================================================
   API STATUS
   ============================================================ */

async function checkAPIStatus() {

    if (!apiStatus) {
        return;
    }

    try {

        const response =
            await fetch(
                `${API_URL}/`,
                {
                    method: "GET"
                }
            );

        if (!response.ok) {
            throw new Error("API unavailable");
        }

        apiStatus.textContent =
            "API Online";

        apiStatus.classList.remove(
            "offline"
        );

        apiStatus.classList.add(
            "online"
        );

    } catch (error) {

        apiStatus.textContent =
            "API Offline";

        apiStatus.classList.remove(
            "online"
        );

        apiStatus.classList.add(
            "offline"
        );

    }
}


/* ============================================================
   FILE UPLOAD SETUP
   ============================================================ */

function setupFileUpload() {

    /* --------------------------------------------------------
       File input
       -------------------------------------------------------- */

    if (fileInput) {

        fileInput.addEventListener(
            "change",
            handleFileSelection
        );

    }


    /* --------------------------------------------------------
       Browse File button
       -------------------------------------------------------- */

    if (browseButton && fileInput) {

        browseButton.addEventListener(
            "click",
            (event) => {

                event.preventDefault();

                event.stopPropagation();

                fileInput.click();

            }
        );

    }


    /* --------------------------------------------------------
       Drop zone
       -------------------------------------------------------- */

    if (uploadArea) {

        uploadArea.addEventListener(
            "dragover",
            (event) => {

                event.preventDefault();

                uploadArea.classList.add(
                    "dragover"
                );

            }
        );


        uploadArea.addEventListener(
            "dragleave",
            (event) => {

                event.preventDefault();

                uploadArea.classList.remove(
                    "dragover"
                );

            }
        );


        uploadArea.addEventListener(
            "drop",
            (event) => {

                event.preventDefault();

                uploadArea.classList.remove(
                    "dragover"
                );

                const files =
                    event.dataTransfer.files;

                if (
                    files &&
                    files.length > 0
                ) {

                    processSelectedFile(
                        files[0]
                    );

                }

            }
        );


        /* ----------------------------------------------------
           Clicking the drop zone opens file picker
           ---------------------------------------------------- */

        uploadArea.addEventListener(
            "click",
            (event) => {

                if (
                    event.target.closest(
                        "#browseButton"
                    )
                ) {

                    return;

                }

                if (fileInput) {

                    fileInput.click();

                }

            }
        );

    }

}


/* ============================================================
   BUTTON SETUP
   ============================================================ */

function setupButtons() {

    if (analyzeButton) {

        analyzeButton.addEventListener(
            "click",
            analyzeEmail
        );

    }

    if (resetButton) {

        resetButton.addEventListener(
            "click",
            resetApplication
        );

    }

}


/* ============================================================
   FILE SELECTION
   ============================================================ */

function handleFileSelection(
    event
) {

    const files =
        event.target.files;

    if (
        !files ||
        files.length === 0
    ) {

        return;

    }

    processSelectedFile(
        files[0]
    );

}


/* ============================================================
   PROCESS SELECTED FILE
   ============================================================ */

function processSelectedFile(
    file
) {

    clearError();

    if (!file) {
        return;
    }

    if (
        !file.name
            .toLowerCase()
            .endsWith(".eml")
    ) {

        showError(
            "Only .eml email files are supported."
        );

        selectedFile = null;

        if (selectedFileElement) {

            selectedFileElement.textContent =
                "";

        }

        if (analyzeButton) {

            analyzeButton.disabled =
                true;

        }

        return;
    }

    selectedFile =
        file;

    if (selectedFileElement) {

        selectedFileElement.textContent =
            `Selected: ${file.name}`;

    }

    if (analyzeButton) {

        analyzeButton.disabled =
            false;

    }

}


/* ============================================================
   ANALYZE EMAIL
   ============================================================ */

async function analyzeEmail() {

    clearError();

    if (!selectedFile) {

        showError(
            "Please select an .eml file first."
        );

        return;

    }

    const formData =
        new FormData();

    formData.append(
        "file",
        selectedFile
    );

    setLoadingState(
        true
    );

    try {

        const response =
            await fetch(
                `${API_URL}/analyze`,
                {
                    method: "POST",
                    body: formData
                }
            );

        let data;

        try {

            data =
                await response.json();

        } catch (jsonError) {

            throw new Error(
                "The API returned an invalid response."
            );

        }

        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Email analysis failed."
            );

        }

        displayResults(
            data
        );

    } catch (error) {

        console.error(
            "Analysis error:",
            error
        );

        showError(
            error.message ||
            "Unable to analyze email."
        );

    } finally {

        setLoadingState(
            false
        );

    }

}


/* ============================================================
   LOADING STATE
   ============================================================ */

function setLoadingState(
    loading
) {

    if (loadingState) {

        if (loading) {

            loadingState.classList.remove(
                "hidden"
            );

        } else {

            loadingState.classList.add(
                "hidden"
            );

        }

    }

    if (analyzeButton) {

        analyzeButton.disabled =
            loading ||
            !selectedFile;

        if (loading) {

            analyzeButton.textContent =
                "Analyzing...";

        } else {

            analyzeButton.textContent =
                "Analyze Email";

        }

    }

}


/* ============================================================
   DISPLAY RESULTS
   ============================================================ */

function displayResults(
    data
) {

    if (!data) {
        return;
    }

    const results =
        data.results ||
        data;

    displayEmailOverview(
        data
    );

    displayOverallRisk(
        results
    );

    displayStatistics(
        results
    );

    displaySummary(
        results
    );

    displayURLResults(
        results.url_results
    );

    displayAttachmentResults(
        results.attachment_results
    );

    displayHeaderResults(
        results.header_results
    );

    displayAuthenticationResults(
        results.authentication_results
    );

    displayCorrelationResults(
        results.correlation_results
    );


    if (resultsSection) {

        resultsSection.classList.remove(
            "hidden"
        );

        setTimeout(
            () => {

                resultsSection.scrollIntoView(
                    {
                        behavior: "smooth",
                        block: "start"
                    }
                );

            },
            100
        );

    }

}


/* ============================================================
   EMAIL OVERVIEW
   ============================================================ */

function displayEmailOverview(
    data
) {

    const parsedEmail =
        data.parsed_email ||
        data.email ||
        data.email_data ||
        data;

    setText(
        "emailFrom",
        parsedEmail.from
    );

    setText(
        "emailTo",
        parsedEmail.to
    );

    setText(
        "emailReplyTo",
        parsedEmail.reply_to
    );

    setText(
        "emailSubject",
        parsedEmail.subject
    );

    setText(
        "emailDate",
        parsedEmail.date
    );

    setText(
        "emailMessageId",
        parsedEmail.message_id
    );

}


/* ============================================================
   OVERALL RISK
   ============================================================ */

function displayOverallRisk(
    results
) {

    const riskLevelElement =
        document.getElementById(
            "riskLevel"
        );

    const riskScoreElement =
        document.getElementById(
            "riskScore"
        );

    const score =
        getRiskScore(
            results
        );

    const risk =
        results.overall_risk ||
        classifyRisk(
            score
        );

    if (riskLevelElement) {

        riskLevelElement.textContent =
            risk;

        riskLevelElement.className =
            "risk-level";

        riskLevelElement.classList.add(
            getRiskClass(
                risk
            )
        );

    }

    if (riskScoreElement) {

        riskScoreElement.textContent =
            `${score}/100`;

    }

}


/* ============================================================
   RISK CLASS
   ============================================================ */

function getRiskClass(
    risk
) {

    if (!risk) {
        return "";
    }

    return String(risk)
        .toLowerCase()
        .replace(
            /\s+/g,
            "-"
        );

}


/* ============================================================
   RISK CLASSIFICATION
   ============================================================ */

function classifyRisk(
    score
) {

    if (score >= 60) {
        return "CRITICAL";
    }

    if (score >= 40) {
        return "HIGH";
    }

    if (score >= 20) {
        return "MEDIUM";
    }

    return "LOW";

}


/* ============================================================
   STATISTICS
   ============================================================ */

function displayStatistics(
    results
) {

    const urls =
        Array.isArray(
            results.url_results
        )
            ? results.url_results.length
            : 0;

    const attachments =
        Array.isArray(
            results.attachment_results
        )
            ? results.attachment_results.length
            : 0;

    const headerFindings =
        getIndicators(
            results.header_results
        ).length;

    const authFindings =
        getIndicators(
            results.authentication_results
        ).length;

    setText(
        "urlCount",
        urls
    );

    setText(
        "attachmentCount",
        attachments
    );

    setText(
        "headerCount",
        headerFindings
    );

    setText(
        "authCount",
        authFindings
    );

}


/* ============================================================
   DETECTION SUMMARY
   ============================================================ */

function displaySummary(
    results
) {

    const container =
        document.getElementById(
            "summaryList"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    const summary =
        Array.isArray(
            results.summary
        )
            ? results.summary
            : [];

    if (summary.length === 0) {

        const empty =
            document.createElement(
                "li"
            );

        empty.className =
            "empty-state";

        empty.textContent =
            "No significant indicators were identified.";

        container.appendChild(
            empty
        );

        return;

    }

    summary.forEach(
        (item) => {

            const element =
                document.createElement(
                    "li"
                );

            element.className =
                "summary-item";

            element.textContent =
                item;

            container.appendChild(
                element
            );

        }
    );

}


/* ============================================================
   URL ANALYSIS
   ============================================================ */

function displayURLResults(
    urlResults
) {

    const container =
        document.getElementById(
            "urlResults"
        );

    const card =
        document.getElementById(
            "urlResultsCard"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    if (
        !Array.isArray(
            urlResults
        ) ||
        urlResults.length === 0
    ) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    if (card) {

        card.classList.remove(
            "hidden"
        );

    }

    urlResults.forEach(
        (url, index) => {

            const score =
                getRiskScore(
                    url
                );

            const indicators =
                getIndicators(
                    url
                );

            const wrapper =
                document.createElement(
                    "div"
                );

            wrapper.className =
                "result-item";

            const title =
                document.createElement(
                    "div"
                );

            title.className =
                "result-item-title";

            title.textContent =
                `URL ${index + 1}`;

            const urlElement =
                document.createElement(
                    "div"
                );

            urlElement.className =
                "result-item-description";

            urlElement.textContent =
                url.raw_url ||
                url.url ||
                "Unknown URL";

            const scoreElement =
                document.createElement(
                    "div"
                );

            scoreElement.className =
                "result-item-score";

            scoreElement.textContent =
                `Risk Score: ${score}`;

            wrapper.appendChild(
                title
            );

            wrapper.appendChild(
                urlElement
            );

            wrapper.appendChild(
                scoreElement
            );

            if (
                indicators.length > 0
            ) {

                const indicatorElement =
                    document.createElement(
                        "div"
                    );

                indicatorElement.className =
                    "result-item-indicators";

                indicatorElement.textContent =
                    indicators
                        .map(
                            formatIndicatorText
                        )
                        .join(
                            "  "
                        );

                wrapper.appendChild(
                    indicatorElement
                );

            }

            container.appendChild(
                wrapper
            );

        }
    );

}


/* ============================================================
   ATTACHMENT ANALYSIS
   ============================================================ */

function displayAttachmentResults(
    attachmentResults
) {

    const container =
        document.getElementById(
            "attachmentResults"
        );

    const card =
        document.getElementById(
            "attachmentResultsCard"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    if (
        !Array.isArray(
            attachmentResults
        ) ||
        attachmentResults.length === 0
    ) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    if (card) {

        card.classList.remove(
            "hidden"
        );

    }

    attachmentResults.forEach(
        (attachment, index) => {

            const filename =
                attachment.filename ||
                attachment.name ||
                `Attachment ${index + 1}`;

            const score =
                getRiskScore(
                    attachment
                );

            const indicators =
                getIndicators(
                    attachment
                );

            const item =
                createResultItem(
                    `Attachment ${index + 1}`,
                    filename,
                    score,
                    indicators
                );

            container.appendChild(
                item
            );

        }
    );

}


/* ============================================================
   HEADER ANALYSIS
   ============================================================ */

function displayHeaderResults(
    headerResults
) {

    const container =
        document.getElementById(
            "headerResults"
        );

    const card =
        document.getElementById(
            "headerResultsCard"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    if (!headerResults) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    const indicators =
        getIndicators(
            headerResults
        );

    const score =
        getRiskScore(
            headerResults
        );

    if (
        indicators.length === 0 &&
        score === 0
    ) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    if (card) {

        card.classList.remove(
            "hidden"
        );

    }

    indicators.forEach(
        (indicator, index) => {

            const item =
                createResultItem(
                    `Header Finding ${index + 1}`,
                    formatIndicatorText(
                        indicator
                    ),
                    score,
                    []
                );

            container.appendChild(
                item
            );

        }
    );

}


/* ============================================================
   AUTHENTICATION ANALYSIS
   ============================================================ */

function displayAuthenticationResults(
    authenticationResults
) {

    const container =
        document.getElementById(
            "authenticationResults"
        );

    const card =
        document.getElementById(
            "authenticationResultsCard"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    if (!authenticationResults) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    const indicators =
        getIndicators(
            authenticationResults
        );

    const score =
        getRiskScore(
            authenticationResults
        );

    if (
        indicators.length === 0 &&
        score === 0
    ) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    if (card) {

        card.classList.remove(
            "hidden"
        );

    }

    indicators.forEach(
        (indicator, index) => {

            const item =
                createResultItem(
                    `Authentication Finding ${index + 1}`,
                    formatIndicatorText(
                        indicator
                    ),
                    score,
                    []
                );

            container.appendChild(
                item
            );

        }
    );

}


/* ============================================================
   CORRELATION ANALYSIS
   ============================================================ */

function displayCorrelationResults(
    correlationResults
) {

    const container =
        document.getElementById(
            "correlationResults"
        );

    const card =
        document.getElementById(
            "correlationResultsCard"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    if (!correlationResults) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    const indicators =
        getIndicators(
            correlationResults
        );

    const categories =
        Array.isArray(
            correlationResults.categories
        )
            ? correlationResults.categories
            : [];

    const score =
        getRiskScore(
            correlationResults
        );

    if (
        indicators.length === 0 &&
        categories.length === 0 &&
        score === 0
    ) {

        if (card) {

            card.classList.add(
                "hidden"
            );

        }

        return;

    }

    if (card) {

        card.classList.remove(
            "hidden"
        );

    }


    /* --------------------------------------------------------
       Correlation Risk Score
       -------------------------------------------------------- */

    if (score > 0) {

        const scoreItem =
            document.createElement("div");

        scoreItem.className =
            "result-item correlation-score-item";

        const scoreTitle =
            document.createElement("div");

        scoreTitle.className =
            "result-item-title";

        scoreTitle.textContent =
            "Correlation Risk Score";

        const scoreDescription =
            document.createElement("div");

        scoreDescription.className =
            "result-item-description";

        scoreDescription.textContent =
            `${score}/100`;

        scoreItem.appendChild(
            scoreTitle
        );

        scoreItem.appendChild(
            scoreDescription
        );

        container.appendChild(
            scoreItem
        );

    }


    /* --------------------------------------------------------
       Detection Categories
       -------------------------------------------------------- */

    if (
        categories.length > 0
    ) {

        const heading =
            document.createElement(
                "div"
            );

        heading.className =
            "correlation-section-heading";

        heading.textContent =
            "Detection Categories";

        container.appendChild(
            heading
        );

        categories.forEach(
            (category) => {

                const item =
                    createResultItem(
                        "Detected Category",
                        formatCorrelationText(
                            category
                        ),
                        undefined,
                        []
                    );

                container.appendChild(
                    item
                );

            }
        );

    }


    /* --------------------------------------------------------
       Correlation Findings
       -------------------------------------------------------- */

    if (
        indicators.length > 0
    ) {

        const heading =
            document.createElement(
                "div"
            );

        heading.className =
            "correlation-section-heading";

        heading.textContent =
            "Correlation Findings";

        container.appendChild(
            heading
        );

        indicators.forEach(
            (indicator, index) => {

                const item =
                    createResultItem(
                        `Finding ${index + 1}`,
                        formatCorrelationText(
                            indicator
                        ),
                        undefined,
                        []
                    );

                container.appendChild(
                    item
                );

            }
        );

    }

}


/* ============================================================
   FORMAT CORRELATION TEXT
   ============================================================ */

function formatCorrelationText(
    value
) {

    if (!value) {
        return "Unknown";
    }

    const text =
        String(value)
            .replace(
                /_/g,
                " "
            );

    return (
        text.charAt(0).toUpperCase() +
        text.slice(1)
    );

}


/* ============================================================
   RESULT ITEM
   ============================================================ */

function createResultItem(
    title,
    description,
    score,
    indicators
) {

    const wrapper =
        document.createElement(
            "div"
        );

    wrapper.className =
        "result-item";


    const heading =
        document.createElement(
            "div"
        );

    heading.className =
        "result-item-title";

    heading.textContent =
        title;


    const body =
        document.createElement(
            "div"
        );

    body.className =
        "result-item-description";

    body.textContent =
        description ||
        "No description available.";


    wrapper.appendChild(
        heading
    );

    wrapper.appendChild(
        body
    );


    if (
        score !== undefined &&
        score !== null
    ) {

        const scoreElement =
            document.createElement(
                "div"
            );

        scoreElement.className =
            "result-item-score";

        scoreElement.textContent =
            `Risk Score: ${score}`;

        wrapper.appendChild(
            scoreElement
        );

    }


    if (
        Array.isArray(
            indicators
        ) &&
        indicators.length > 0
    ) {

        const indicatorElement =
            document.createElement(
                "div"
            );

        indicatorElement.className =
            "result-item-indicators";

        indicatorElement.textContent =
            indicators
                .map(
                    formatIndicatorText
                )
                .join(
                    "  "
                );

        wrapper.appendChild(
            indicatorElement
        );

    }

    return wrapper;

}


/* ============================================================
   GET INDICATORS
   ============================================================ */

function getIndicators(
    object
) {

    if (!object) {
        return [];
    }

    if (
        Array.isArray(
            object.indicators
        )
    ) {

        return object.indicators;

    }

    return [];

}


/* ============================================================
   GET RISK SCORE
   ============================================================ */

function getRiskScore(
    object
) {

    if (!object) {
        return 0;
    }

    const score =
        Number(
            object.risk_score ??
            object.overall_score ??
            object.score ??
            0
        );

    if (
        Number.isNaN(
            score
        )
    ) {

        return 0;

    }

    return score;

}


/* ============================================================
   FORMAT INDICATOR TEXT
   ============================================================ */

function formatIndicatorText(
    value
) {

    if (!value) {
        return "Unknown";
    }

    const acronyms = {
        spf: "SPF",
        dkim: "DKIM",
        dmarc: "DMARC",
        http: "HTTP",
        https: "HTTPS",
        ip: "IP",
        url: "URL",
        mime: "MIME",
        pdf: "PDF",
        exe: "EXE",
        at: "@"
    };

    return String(value)
        .replace(
            /_/g,
            " "
        )
        .split(" ")
        .map(
            (word) => {

                const lower =
                    word.toLowerCase();

                if (
                    acronyms[lower]
                ) {
                    return acronyms[lower];
                }

                return (
                    lower.charAt(0).toUpperCase() +
                    lower.slice(1)
                );

            }
        )
        .join(" ");

}


/* ============================================================
   SET TEXT
   ============================================================ */

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );

    if (!element) {
        return;
    }

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        element.textContent =
            "—";

        return;

    }

    element.textContent =
        value;

}


/* ============================================================
   ERROR HANDLING
   ============================================================ */

function showError(
    message
) {

    if (!errorMessage) {
        return;
    }

    errorMessage.textContent =
        message;

    errorMessage.classList.remove(
        "hidden"
    );

}


function clearError() {

    if (!errorMessage) {
        return;
    }

    errorMessage.textContent =
        "";

    errorMessage.classList.add(
        "hidden"
    );

}


/* ============================================================
   RESET APPLICATION
   ============================================================ */

function resetApplication() {

    selectedFile =
        null;


    if (fileInput) {

        fileInput.value =
            "";

    }


    if (selectedFileElement) {

        selectedFileElement.textContent =
            "";

    }


    if (analyzeButton) {

        analyzeButton.disabled =
            true;

        analyzeButton.textContent =
            "Analyze Email";

    }


    clearError();


    if (loadingState) {

        loadingState.classList.add(
            "hidden"
        );

    }


    if (resultsSection) {

        resultsSection.classList.add(
            "hidden"
        );

    }


    const cards = [
        "urlResultsCard",
        "attachmentResultsCard",
        "headerResultsCard",
        "authenticationResultsCard",
        "correlationResultsCard"
    ];


    cards.forEach(
        (id) => {

            const card =
                document.getElementById(
                    id
                );

            if (card) {

                card.classList.add(
                    "hidden"
                );

            }

        }
    );


    const containers = [
        "summaryList",
        "urlResults",
        "attachmentResults",
        "headerResults",
        "authenticationResults",
        "correlationResults"
    ];


    containers.forEach(
        (id) => {

            const container =
                document.getElementById(
                    id
                );

            if (container) {

                container.innerHTML =
                    "";

            }

        }
    );


    setText(
        "emailFrom",
        "—"
    );

    setText(
        "emailTo",
        "—"
    );

    setText(
        "emailReplyTo",
        "—"
    );

    setText(
        "emailSubject",
        "—"
    );

    setText(
        "emailDate",
        "—"
    );

    setText(
        "emailMessageId",
        "—"
    );

    setText(
        "riskLevel",
        "—"
    );

    setText(
        "riskScore",
        "0/100"
    );

    setText(
        "urlCount",
        "0"
    );

    setText(
        "attachmentCount",
        "0"
    );

    setText(
        "headerCount",
        "0"
    );

    setText(
        "authCount",
        "0"
    );

}

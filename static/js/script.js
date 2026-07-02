document.addEventListener('DOMContentLoaded', () => {
    // DOM elements selection
    const fileInput = document.getElementById('fileInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const uploadStatus = document.getElementById('uploadStatus');
    const heroSection = document.getElementById('heroSection');
    
    // Step progress container
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const stepRead = document.getElementById('step-read');
    const stepDetect = document.getElementById('step-detect');
    const stepRisk = document.getElementById('step-risk');
    const stepSummary = document.getElementById('step-summary');
    const stepQa = document.getElementById('step-qa');

    // Layout
    const appLayout = document.getElementById('appLayout');

    // Dashboard card fields
    const dbFileName = document.getElementById('dbFileName');
    const dbFileType = document.getElementById('dbFileType');
    const dbFileSize = document.getElementById('dbFileSize');
    const dbTimestamp = document.getElementById('dbTimestamp');
    const dbTotalSensitive = document.getElementById('dbTotalSensitive');
    const dbCategoriesCount = document.getElementById('dbCategoriesCount');
    const dbSummaryStatus = document.getElementById('dbSummaryStatus');
    const dbRiskLevel = document.getElementById('dbRiskLevel');

    // Findings section
    const riskLevel = document.getElementById('riskLevel');
    const riskScore = document.getElementById('riskScore');
    const riskReasonsList = document.getElementById('riskReasonsList');
    const findingsList = document.getElementById('findingsList');
    const showRedactedBtn = document.getElementById('showRedactedBtn');
    const redactedText = document.getElementById('redactedText');

    // Report Downloads
    const downloadPdfBtn = document.getElementById('downloadPdfBtn');
    const downloadTxtBtn = document.getElementById('downloadTxtBtn');
    const downloadCsvBtn = document.getElementById('downloadCsvBtn');
    const downloadJsonBtn = document.getElementById('downloadJsonBtn');
    
    // AI Summary
    const generateSummaryBtn = document.getElementById('generateSummaryBtn');
    const summaryOutput = document.getElementById('summaryOutput');
    const summaryCardsContainer = document.getElementById('summaryCardsContainer');
    const summaryObservations = document.getElementById('summaryObservations');
    const summaryRisks = document.getElementById('summaryRisks');
    const summaryRemediation = document.getElementById('summaryRemediation');
    const summaryRecommendations = document.getElementById('summaryRecommendations');
    
    // QA Chatbot elements
    const questionInput = document.getElementById('questionInput');
    const askBtn = document.getElementById('askBtn');
    const chatHistory = document.getElementById('chatHistory');
    const clearChatBtn = document.getElementById('clearChatBtn');
    const exportChatPdfBtn = document.getElementById('exportChatPdfBtn');
    const exportChatTxtBtn = document.getElementById('exportChatTxtBtn');
    const suggestionChips = document.getElementById('suggestionChips');
    const charCounter = document.getElementById('charCounter');
    const chatNotification = document.getElementById('chatNotification');

    // Category mapping to Font Awesome icons
    const categoryIcons = {
        "Aadhaar Number": "fa-fingerprint",
        "PAN Number": "fa-id-card",
        "Email Address": "fa-envelope",
        "Phone Number": "fa-phone",
        "Credit Card Number": "fa-credit-card",
        "Bank Account Number": "fa-money-check-dollar",
        "IFSC Code": "fa-building-columns",
        "API Key / Secret": "fa-lock",
        "Password": "fa-key",
        "Employee ID": "fa-user-gear",
        "IP Address": "fa-network-wired"
    };

    // Chat states
    let conversationHistory = [];
    let isGenerating = false;
    let hasAnalyzed = false;

    // Helper to escape HTML characters
    function escapeHTML(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Custom client-side markdown bullet/list renderer to prevent library deps
    function renderMarkdown(text) {
        const lines = text.split('\n');
        let inList = false;
        let inNumList = false;
        let html = '';
        
        lines.forEach(line => {
            const bulletMatch = line.match(/^[ \t]*[\*\-][ \t]+(.*)/);
            const numMatch = line.match(/^[ \t]*\d+\.[ \t]+(.*)/);
            
            if (bulletMatch) {
                if (inNumList) {
                    html += '</ol>';
                    inNumList = false;
                }
                if (!inList) {
                    html += '<ul>';
                    inList = true;
                }
                html += `<li>${escapeHTML(bulletMatch[1])}</li>`;
            } else if (numMatch) {
                if (inList) {
                    html += '</ul>';
                    inList = false;
                }
                if (!inNumList) {
                    html += '<ol>';
                    inNumList = true;
                }
                html += `<li>${escapeHTML(numMatch[1])}</li>`;
            } else {
                if (inList) {
                    html += '</ul>';
                    inList = false;
                }
                if (inNumList) {
                    html += '</ol>';
                    inNumList = false;
                }
                
                const trimmed = line.trim();
                if (trimmed) {
                    let processed = escapeHTML(trimmed);
                    // Bold tags
                    processed = processed.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
                    html += `<p>${processed}</p>`;
                }
            }
        });
        
        if (inList) html += '</ul>';
        if (inNumList) html += '</ol>';
        
        return html;
    }

    // Helper to sleep for simulated UX steps
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

    // Reset progress steps UI
    function resetProgress() {
        progressBar.style.width = '0%';
        [stepRead, stepDetect, stepRisk, stepSummary, stepQa].forEach(step => {
            step.classList.remove('active', 'completed');
        });
    }

    // Parse AI compliance report into 4 cards
    function parseSummary(text) {
        const sections = {
            observations: 'Not available.',
            risks: 'Not available.',
            remediation: 'Not available.',
            recommendations: 'Not available.'
        };
        
        const header1 = "1. Compliance Observations";
        const header2 = "2. Security Risks";
        const header3 = "3. Suggested Remediation";
        const header4 = "4. Future Recommendations";
        
        const index1 = text.indexOf(header1);
        const index2 = text.indexOf(header2);
        const index3 = text.indexOf(header3);
        const index4 = text.indexOf(header4);
        
        if (index1 !== -1 && index2 !== -1 && index3 !== -1 && index4 !== -1) {
            sections.observations = text.substring(index1 + header1.length, index2).trim();
            sections.risks = text.substring(index2 + header2.length, index3).trim();
            sections.remediation = text.substring(index3 + header3.length, index4).trim();
            sections.recommendations = text.substring(index4 + header4.length).trim();
        } else {
            sections.observations = text;
        }
        
        return sections;
    }

    // Render risk badge, score and reasons explanation list
    function renderRisk(risk) {
        riskLevel.textContent = risk.level;
        riskLevel.classList.remove('low', 'medium', 'high');
        
        const levelLower = (risk.level || '').toLowerCase();
        if (levelLower.includes('low')) {
            riskLevel.classList.add('low');
            dbRiskLevel.className = 'dashboard-value text-low';
            dbRiskLevel.style.color = '#10b981';
        } else if (levelLower.includes('medium')) {
            riskLevel.classList.add('medium');
            dbRiskLevel.className = 'dashboard-value text-medium';
            dbRiskLevel.style.color = '#f59e0b';
        } else if (levelLower.includes('high')) {
            riskLevel.classList.add('high');
            dbRiskLevel.className = 'dashboard-value text-high';
            dbRiskLevel.style.color = '#ef4444';
        }
        
        dbRiskLevel.textContent = risk.level;
        riskScore.textContent = risk.score;

        // Render reasons list
        riskReasonsList.innerHTML = '';
        if (risk.reasons && risk.reasons.length > 0) {
            risk.reasons.forEach(reason => {
                const li = document.createElement('li');
                li.innerHTML = escapeHTML(reason);
                riskReasonsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = '• No sensitive threats detected.';
            riskReasonsList.appendChild(li);
        }
    }

    // Render findings list
    function renderFindings(findings) {
        let html = '';
        for (const [category, items] of Object.entries(findings)) {
            const escCategory = escapeHTML(category);
            const count = items.length;
            const iconName = categoryIcons[category] || "fa-triangle-exclamation";
            
            let chips = '';
            items.forEach(item => {
                chips += `<span class="finding-chip">${escapeHTML(item)}</span>`;
            });
            
            html += `
            <div class="findings-category">
                <div class="findings-category-title">
                    <i class="fa-solid ${iconName}"></i>
                    <span>${escCategory} (${count} found)</span>
                </div>
                <div class="findings-items">
                    ${chips}
                </div>
            </div>`;
        }
        
        findingsList.innerHTML = html || '<p>No sensitive data found.</p>';
    }

    // Action: Analyze document
    analyzeBtn.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if (!file) {
            uploadStatus.innerHTML = '<span style="color: var(--risk-high-text);"><i class="fa-solid fa-circle-xmark"></i> Please select a document to analyze.</span>';
            return;
        }

        // Initialize UI states
        analyzeBtn.disabled = true;
        uploadStatus.innerHTML = '';
        progressContainer.removeAttribute('hidden');
        resetProgress();

        // Step 1: Reading document
        stepRead.classList.add('active');
        progressBar.style.width = '20%';
        await sleep(600);

        const formData = new FormData();
        formData.append('file', file);

        try {
            // Step 2: Detecting sensitive data
            stepRead.classList.remove('active');
            stepRead.classList.add('completed');
            stepDetect.classList.add('active');
            progressBar.style.width = '50%';
            await sleep(600);

            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();

            if (response.ok) {
                // Step 3: Calculating risk
                stepDetect.classList.remove('active');
                stepDetect.classList.add('completed');
                stepRisk.classList.add('active');
                progressBar.style.width = '85%';
                await sleep(500);

                stepRisk.classList.remove('active');
                stepRisk.classList.add('completed');
                progressBar.style.width = '100%';
                await sleep(300);

                uploadStatus.innerHTML = '<span style="color: #10b981; font-weight: 600;"><i class="fa-solid fa-circle-check"></i> Analysis complete!</span>';
                
                // Hide landing page hero section
                heroSection.setAttribute('hidden', '');

                // Unhide Layout Wrapper
                appLayout.removeAttribute('hidden');
                hasAnalyzed = true;

                // Populate Dashboard Cards
                const metadata = data.metadata;
                dbFileName.textContent = metadata.file_name;
                dbFileType.textContent = metadata.file_type;
                dbFileSize.textContent = metadata.file_size;
                dbTimestamp.textContent = metadata.timestamp;
                dbTotalSensitive.textContent = metadata.findings_count;
                dbCategoriesCount.textContent = metadata.categories_count;
                dbSummaryStatus.textContent = "Not Generated";
                dbSummaryStatus.style.color = 'var(--text-muted)';

                // Bind Report Download href links
                downloadPdfBtn.href = '/api/report/pdf';
                downloadTxtBtn.href = '/api/report/txt';
                downloadCsvBtn.href = '/api/report/csv';
                downloadJsonBtn.href = '/api/report/json';

                // Populate Risk and Findings
                renderRisk(data.risk);
                renderFindings(data.findings);
                
                // Clear previous chat conversation dynamically
                if (conversationHistory.length > 0) {
                    clearChatHistory();
                    showChatNotification("New document uploaded. Previous conversation has been cleared.");
                }
                
                // Clear other layouts
                redactedText.setAttribute('hidden', '');
                redactedText.textContent = '';
                showRedactedBtn.innerHTML = '<i class="fa-solid fa-eye-slash"></i> Show Redacted Version';
                summaryOutput.innerHTML = '';
                summaryCardsContainer.setAttribute('hidden', '');
            } else {
                resetProgress();
                progressContainer.setAttribute('hidden', '');
                uploadStatus.innerHTML = `<span style="color: var(--risk-high-text); font-weight: 600;"><i class="fa-solid fa-triangle-exclamation"></i> Error: ${escapeHTML(data.error || 'Failed to analyze document')}</span>`;
            }
        } catch (e) {
            resetProgress();
            progressContainer.setAttribute('hidden', '');
            uploadStatus.innerHTML = `<span style="color: var(--risk-high-text); font-weight: 600;"><i class="fa-solid fa-triangle-exclamation"></i> Error: ${escapeHTML(e.message)}</span>`;
        } finally {
            analyzeBtn.disabled = false;
        }
    });

    // Action: Toggle and show redacted version
    showRedactedBtn.addEventListener('click', async () => {
        showRedactedBtn.disabled = true;
        try {
            const response = await fetch('/api/redact');
            const data = await response.json();
            
            if (response.ok) {
                redactedText.textContent = data.redacted_text;
                if (redactedText.hasAttribute('hidden')) {
                    redactedText.removeAttribute('hidden');
                    showRedactedBtn.innerHTML = '<i class="fa-solid fa-eye"></i> Hide Redacted Version';
                } else {
                    redactedText.setAttribute('hidden', '');
                    showRedactedBtn.innerHTML = '<i class="fa-solid fa-eye-slash"></i> Show Redacted Version';
                }
            } else {
                alert(data.error || 'Failed to fetch redacted text');
            }
        } catch (e) {
            alert('Error fetching redaction: ' + e.message);
        } finally {
            showRedactedBtn.disabled = false;
        }
    });

    // Action: Generate compliance summary
    generateSummaryBtn.addEventListener('click', async () => {
        generateSummaryBtn.disabled = true;
        
        progressContainer.removeAttribute('hidden');
        stepSummary.classList.add('active');
        summaryOutput.innerHTML = '<em>🤖 Generating compliance report... Please wait...</em>';
        summaryCardsContainer.setAttribute('hidden', '');

        try {
            const response = await fetch('/api/summary', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();

            if (response.ok) {
                stepSummary.classList.remove('active');
                stepSummary.classList.add('completed');
                
                dbSummaryStatus.textContent = "Generated";
                dbSummaryStatus.style.color = '#10b981';
                
                summaryOutput.innerHTML = '';
                
                const parsed = parseSummary(data.summary);
                summaryObservations.innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin: 0; line-height: 1.6; color: var(--text-main);">${escapeHTML(parsed.observations)}</pre>`;
                summaryRisks.innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin: 0; line-height: 1.6; color: var(--text-main);">${escapeHTML(parsed.risks)}</pre>`;
                summaryRemediation.innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin: 0; line-height: 1.6; color: var(--text-main);">${escapeHTML(parsed.remediation)}</pre>`;
                summaryRecommendations.innerHTML = `<pre style="white-space: pre-wrap; font-family: inherit; margin: 0; line-height: 1.6; color: var(--text-main);">${escapeHTML(parsed.recommendations)}</pre>`;
                
                summaryCardsContainer.removeAttribute('hidden');
            } else {
                stepSummary.classList.remove('active');
                summaryOutput.innerHTML = `<span style="color: var(--risk-high-text); font-weight: 600;"><i class="fa-solid fa-triangle-exclamation"></i> Error: ${escapeHTML(data.error || 'Failed to generate compliance report')}</span>`;
            }
        } catch (e) {
            stepSummary.classList.remove('active');
            summaryOutput.innerHTML = `<span style="color: var(--risk-high-text); font-weight: 600;"><i class="fa-solid fa-triangle-exclamation"></i> Error: ${escapeHTML(e.message)}</span>`;
        } finally {
            generateSummaryBtn.disabled = false;
        }
    });

    // ==================================================
    // CHATBOT INTERACTIVITY AND EXPORT CONTROLS
    // ==================================================

    // Helper to get formatted timestamp (HH:MM AM/PM)
    function getFormattedTime() {
        const date = new Date();
        let hours = date.getHours();
        let minutes = date.getMinutes();
        const ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12;
        hours = hours ? hours : 12; // 0 should be 12
        minutes = minutes < 10 ? '0' + minutes : minutes;
        return `${hours}:${minutes} ${ampm}`;
    }

    // Display banner notifications in the chat panel
    function showChatNotification(message) {
        chatNotification.textContent = message;
        chatNotification.removeAttribute('hidden');
        setTimeout(() => {
            chatNotification.setAttribute('hidden', '');
            chatNotification.textContent = '';
        }, 5000); // Fades out after 5 seconds
    }

    // Render message log into DOM
    function renderMessage(sender, text, timestamp) {
        const welcome = chatHistory.querySelector('.chat-welcome');
        if (welcome) welcome.remove();

        const wrapper = document.createElement('div');
        wrapper.className = `chat-message-wrapper ${sender}`;
        
        const meta = document.createElement('div');
        meta.className = 'message-meta';

        // nameSpan.textContent = sender === 'user' ? 'You' : 'SecureScan AI';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'sender-name';
        nameSpan.textContent = sender === 'user' ? 'You' : 'SecureScan AI';

        const timeSpan = document.createElement('span');
        timeSpan.className = 'message-time';
        timeSpan.textContent = timestamp;

        const avatar = document.createElement('span');
        avatar.className = 'avatar';
        avatar.innerHTML = sender === 'user' ? '<i class="fa-solid fa-user"></i>' : '<i class="fa-solid fa-robot"></i>';

        if (sender === 'user') {
            meta.appendChild(nameSpan);
            meta.appendChild(timeSpan);
            meta.appendChild(avatar);
        } else {
            meta.appendChild(avatar);
            meta.appendChild(nameSpan);
            meta.appendChild(timeSpan);
        }

        const bubble = document.createElement('div');
        bubble.className = 'chat-message-bubble';
        
        if (sender === 'user') {
            bubble.textContent = text;
        } else {
            // Apply custom markdown rendering
            bubble.innerHTML = renderMarkdown(text);
        }

        wrapper.appendChild(meta);
        wrapper.appendChild(bubble);
        chatHistory.appendChild(wrapper);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }

    // Clear chat logic
    function clearChatHistory() {
        conversationHistory = [];
        chatHistory.innerHTML = `
            <div class="chat-welcome">
                <i class="fa-solid fa-comments"></i>
                <p>Ask anything about the uploaded document. Chat history is preserved for this session.</p>
            </div>
        `;
    }

    clearChatBtn.addEventListener('click', () => {
        if (conversationHistory.length > 0) {
            clearChatHistory();
            showChatNotification("Conversation history has been cleared.");
        }
    });

    // Action: Export chat history as PDF or TXT
    async function exportChatLogs(format) {
        if (conversationHistory.length === 0) {
            alert('No conversation history exists to export.');
            return;
        }
        
        try {
            const response = await fetch('/api/chat/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    format: format,
                    messages: conversationHistory
                })
            });
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `chat_history.${format}`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            } else {
                const err = await response.json();
                alert(err.error || 'Failed to export chat logs.');
            }
        } catch (e) {
            alert('Export failed: ' + e.message);
        }
    }

    exportChatPdfBtn.addEventListener('click', () => exportChatLogs('pdf'));
    exportChatTxtBtn.addEventListener('click', () => exportChatLogs('txt'));

    // Question input auto-resize and word counter
    questionInput.addEventListener('input', () => {
        // Reset height
        questionInput.style.height = 'auto';
        // Set new height based on scrollHeight
        questionInput.style.height = (questionInput.scrollHeight) + 'px';
        
        // Update character counter
        const len = questionInput.value.length;
        charCounter.textContent = `${len} / 2000`;
    });

    // Action: Ask QA assistant
    async function handleAsk() {
        if (isGenerating) return; // Prevent duplicate requests
        
        const question = questionInput.value.trim();
        if (!question) {
            alert('Please enter a question.');
            questionInput.focus();
            return;
        }

        isGenerating = true;
        askBtn.disabled = true;
        questionInput.disabled = true;

        const time = getFormattedTime();
        
        // Append user question
        renderMessage('user', question, time);
        conversationHistory.push({ sender: 'user', text: question, timestamp: time });

        // Reset input box height & char counter
        questionInput.value = '';
        questionInput.style.height = 'auto';
        charCounter.textContent = '0 / 2000';
        
        // Show chat active step in upload list (if visible)
        stepQa.classList.remove('completed');
        stepQa.classList.add('active');

        // Append assistant loading animation bubble
        const welcome = chatHistory.querySelector('.chat-welcome');
        if (welcome) welcome.remove();

        const loadingWrapper = document.createElement('div');
        loadingWrapper.id = 'chatLoadingBubble';
        loadingWrapper.className = 'chat-message-wrapper assistant';
        loadingWrapper.innerHTML = `
            <div class="message-meta">
                <span class="avatar"><i class="fa-solid fa-robot"></i></span>
                <span class="sender-name">SecureScan AI</span>
            </div>
            <div class="chat-message-bubble chat-loading">
                <span>🤖 AI is thinking...</span>
                <span class="dot"></span><span class="dot"></span><span class="dot"></span>
            </div>
        `;
        chatHistory.appendChild(loadingWrapper);
        chatHistory.scrollTop = chatHistory.scrollHeight;

        try {
            const response = await fetch('/api/ask', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ question: question })
            });
            const data = await response.json();

            // Remove loading bubble
            const bubble = document.getElementById('chatLoadingBubble');
            if (bubble) bubble.remove();

            const assistantTime = getFormattedTime();

            if (response.ok) {
                renderMessage('assistant', data.answer, assistantTime);
                conversationHistory.push({ sender: 'assistant', text: data.answer, timestamp: assistantTime });
                stepQa.classList.remove('active');
                stepQa.classList.add('completed');
            } else {
                stepQa.classList.remove('active');
                const errMsg = "The AI assistant is temporarily unavailable. Please try again.";
                renderMessage('assistant', errMsg, assistantTime);
                conversationHistory.push({ sender: 'assistant', text: errMsg, timestamp: assistantTime });
            }
        } catch (e) {
            const bubble = document.getElementById('chatLoadingBubble');
            if (bubble) bubble.remove();
            stepQa.classList.remove('active');

            const assistantTime = getFormattedTime();
            const errMsg = "The AI assistant is temporarily unavailable. Please try again.";
            renderMessage('assistant', errMsg, assistantTime);
            conversationHistory.push({ sender: 'assistant', text: errMsg, timestamp: assistantTime });
        } finally {
            isGenerating = false;
            askBtn.disabled = false;
            questionInput.disabled = false;
            questionInput.focus();
            chatHistory.scrollTop = chatHistory.scrollHeight;
        }
    }

    // Trigger QA on button click
    askBtn.addEventListener('click', handleAsk);

    // Trigger QA on Enter key press (Shift+Enter for newline)
    questionInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleAsk();
        }
    });

    // Clickable Suggestion Chips
    suggestionChips.addEventListener('click', (e) => {
        const chip = e.target.closest('.chip-btn');
        if (chip) {
            const question = chip.getAttribute('data-question');
            questionInput.value = question;
            questionInput.focus();
            
            // Adjust input height and counter
            questionInput.style.height = 'auto';
            questionInput.style.height = (questionInput.scrollHeight) + 'px';
            charCounter.textContent = `${question.length} / 2000`;
        }
    });

    // ==================================================
    // AUDIT LOG SYSTEM CLIENT LOGIC
    // ==================================================

    // DOM Elements for tabs & sections
    const scanTabBtn = document.getElementById('scanTabBtn');
    const auditTabBtn = document.getElementById('auditTabBtn');
    const uploadSection = document.getElementById('uploadSection');
    const auditLogSection = document.getElementById('auditLogSection');
    const auditTableBody = document.getElementById('auditTableBody');
    const auditSearchInput = document.getElementById('auditSearchInput');
    const auditEmptyState = document.getElementById('auditEmptyState');
    const detailsModal = document.getElementById('detailsModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const auditTable = document.getElementById('auditTable');

    // Filter selectors
    const filterRisk = document.getElementById('filterRisk');
    const filterStatus = document.getElementById('filterStatus');
    const filterType = document.getElementById('filterType');

    // State Variables
    let auditLogsData = [];
    let currentSortColumn = 'timestamp';
    let currentSortDirection = 'desc';

    // Tab toggling controls
    scanTabBtn.addEventListener('click', () => {
        scanTabBtn.classList.add('active');
        auditTabBtn.classList.remove('active');
        auditLogSection.setAttribute('hidden', '');
        
        // Re-expose scan page parts
        uploadSection.removeAttribute('hidden');
        if (hasAnalyzed) {
            appLayout.removeAttribute('hidden');
            heroSection.setAttribute('hidden', '');
        } else {
            heroSection.removeAttribute('hidden');
            appLayout.setAttribute('hidden', '');
        }
    });

    auditTabBtn.addEventListener('click', async () => {
        auditTabBtn.classList.add('active');
        scanTabBtn.classList.remove('active');
        
        // Hide scan document page parts
        heroSection.setAttribute('hidden', '');
        uploadSection.setAttribute('hidden', '');
        appLayout.setAttribute('hidden', '');
        
        // Show audit logs section
        auditLogSection.removeAttribute('hidden');
        
        // Load log details
        await loadAuditLogs();
    });

    // Fetch and process audit history
    async function loadAuditLogs() {
        try {
            const response = await fetch('/api/audit/history');
            if (response.ok) {
                auditLogsData = await response.json();
                updateSummaryCards(auditLogsData);
                filterAndRenderLogs();
            } else {
                console.error("Failed to load audit history:", response.statusText);
            }
        } catch (e) {
            console.error("Error loading audit history:", e);
        }
    }

    // Update the dynamic summary cards
    function updateSummaryCards(logs) {
        const total = logs.length;
        const high = logs.filter(l => (l.risk_level || '').toUpperCase().includes('HIGH')).length;
        const medium = logs.filter(l => (l.risk_level || '').toUpperCase().includes('MEDIUM')).length;
        const low = logs.filter(l => (l.risk_level || '').toUpperCase().includes('LOW')).length;
        const successCount = logs.filter(l => (l.status || '').toUpperCase() === 'SUCCESS').length;
        
        const successRate = total > 0 ? `${Math.round((successCount / total) * 100)}%` : '0%';
        
        const totalTime = logs.reduce((sum, l) => sum + (l.processing_time || 0), 0);
        const avgTime = total > 0 ? `${(totalTime / total).toFixed(2)}s` : '0.00s';
        
        document.getElementById('cardTotalAnalyses').textContent = total;
        document.getElementById('cardHighRisk').textContent = high;
        document.getElementById('cardMediumRisk').textContent = medium;
        document.getElementById('cardLowRisk').textContent = low;
        document.getElementById('cardSuccessRate').textContent = successRate;
        document.getElementById('cardAvgTime').textContent = avgTime;
    }

    // Sort function for audit logs
    function sortLogs(logs, column, direction) {
        return logs.sort((a, b) => {
            let valA, valB;
            
            if (column === 'timestamp') {
                const parseDate = (str) => {
                    if (!str) return new Date(0);
                    const parts = str.match(/^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})\s+(AM|PM)$/i);
                    if (!parts) return new Date(str);
                    let hours = parseInt(parts[4]);
                    const minutes = parseInt(parts[5]);
                    const ampm = parts[6].toUpperCase();
                    if (ampm === 'PM' && hours < 12) hours += 12;
                    if (ampm === 'AM' && hours === 12) hours = 0;
                    return new Date(parts[1], parts[2] - 1, parts[3], hours, minutes);
                };
                valA = parseDate(a.timestamp);
                valB = parseDate(b.timestamp);
            } else if (column === 'file_name') {
                valA = (a.file_name || '').toLowerCase();
                valB = (b.file_name || '').toLowerCase();
            } else if (column === 'risk_level') {
                const riskOrder = { 'HIGH RISK': 3, 'MEDIUM RISK': 2, 'LOW RISK': 1, 'N/A': 0 };
                valA = riskOrder[(a.risk_level || '').toUpperCase()] || 0;
                valB = riskOrder[(b.risk_level || '').toUpperCase()] || 0;
            } else if (column === 'risk_score') {
                valA = a.risk_score || 0;
                valB = b.risk_score || 0;
            } else if (column === 'status') {
                valA = (a.status || '').toLowerCase();
                valB = (b.status || '').toLowerCase();
            } else if (column === 'total_findings') {
                valA = a.total_findings || 0;
                valB = b.total_findings || 0;
            } else if (column === 'processing_time') {
                valA = a.processing_time || 0;
                valB = b.processing_time || 0;
            } else if (column === 'compliance_frameworks') {
                valA = (a.compliance_frameworks || []).join(', ').toLowerCase();
                valB = (b.compliance_frameworks || []).join(', ').toLowerCase();
            } else {
                valA = a[column];
                valB = b[column];
            }
            
            if (valA < valB) return direction === 'asc' ? -1 : 1;
            if (valA > valB) return direction === 'asc' ? 1 : -1;
            return 0;
        });
    }

    // Filters and renders logic inside table
    function filterAndRenderLogs() {
        const query = auditSearchInput.value.toLowerCase().trim();
        const riskVal = filterRisk.value;
        const statusVal = filterStatus.value;
        const typeVal = filterType.value;
        
        let filtered = [...auditLogsData];
        
        // Search query filter (filename, timestamp, risk, status)
        if (query) {
            filtered = filtered.filter(log => {
                const filename = (log.file_name || '').toLowerCase();
                const timestamp = (log.timestamp || '').toLowerCase();
                const risk = (log.risk_level || '').toLowerCase();
                const status = (log.status || '').toLowerCase();
                
                return filename.includes(query) ||
                       timestamp.includes(query) ||
                       risk.includes(query) ||
                       status.includes(query);
            });
        }
        
        // Risk badge filter
        if (riskVal !== 'all') {
            filtered = filtered.filter(log => {
                const r = (log.risk_level || '').toLowerCase();
                return r.includes(riskVal);
            });
        }
        
        // Status filter
        if (statusVal !== 'all') {
            filtered = filtered.filter(log => {
                const s = (log.status || '').toLowerCase();
                return s === statusVal;
            });
        }
        
        // File type filter
        if (typeVal !== 'all') {
            filtered = filtered.filter(log => {
                const t = (log.file_type || '').toLowerCase();
                return t === typeVal;
            });
        }
        
        // Sort filtered logs
        const sorted = sortLogs(filtered, currentSortColumn, currentSortDirection);
        renderAuditTableRows(sorted);
    }

    // Render list of matching rows
    function renderAuditTableRows(logs) {
        auditTableBody.innerHTML = '';
        
        if (logs.length === 0) {
            auditTable.style.display = 'none';
            auditEmptyState.removeAttribute('hidden');
            return;
        }
        
        auditTable.style.display = 'table';
        auditEmptyState.setAttribute('hidden', '');
        
        logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.addEventListener('click', () => showAuditDetailModal(log));
            
            // Timestamp
            const tdTimestamp = document.createElement('td');
            tdTimestamp.textContent = log.timestamp || 'N/A';
            
            // File Name
            const tdName = document.createElement('td');
            tdName.style.fontWeight = '500';
            tdName.style.color = 'var(--text-main)';
            tdName.textContent = log.file_name || 'N/A';
            
            // Risk Badge
            const tdRisk = document.createElement('td');
            const riskVal = (log.risk_level || 'N/A').toUpperCase();
            let riskClass = 'low';
            if (riskVal.includes('MEDIUM')) riskClass = 'medium';
            else if (riskVal.includes('HIGH')) riskClass = 'high';
            tdRisk.innerHTML = `<span class="risk-badge ${riskClass}">${riskVal}</span>`;
            
            // Risk Score
            const tdRiskScore = document.createElement('td');
            tdRiskScore.textContent = log.risk_score !== undefined ? log.risk_score : 0;
            
            // Status Badge
            const tdStatus = document.createElement('td');
            const statusVal = (log.status || 'FAILED').toUpperCase();
            const statusClass = statusVal === 'SUCCESS' ? 'success' : 'failed';
            tdStatus.innerHTML = `<span class="status-badge ${statusClass}">${statusVal}</span>`;
            
            // Findings count
            const tdFindings = document.createElement('td');
            tdFindings.textContent = log.total_findings !== undefined ? log.total_findings : 0;
            
            // Processing time
            const tdTime = document.createElement('td');
            tdTime.textContent = log.processing_time !== undefined ? `${log.processing_time}s` : 'N/A';
            
            // Compliance
            const tdCompliance = document.createElement('td');
            tdCompliance.textContent = (log.compliance_frameworks && log.compliance_frameworks.length > 0) 
                ? log.compliance_frameworks.join(', ') 
                : 'None';
            
            tr.appendChild(tdTimestamp);
            tr.appendChild(tdName);
            tr.appendChild(tdRisk);
            tr.appendChild(tdRiskScore);
            tr.appendChild(tdStatus);
            tr.appendChild(tdFindings);
            tr.appendChild(tdTime);
            tr.appendChild(tdCompliance);
            
            auditTableBody.appendChild(tr);
        });
    }

    // Show row details inside the Modal overlay
    function showAuditDetailModal(log) {
        document.getElementById('detailTimestamp').textContent = log.timestamp || 'N/A';
        document.getElementById('detailFileName').textContent = log.file_name || 'N/A';
        document.getElementById('detailFileType').textContent = log.file_type || 'N/A';
        document.getElementById('detailFileSize').textContent = log.file_size || 'N/A';
        document.getElementById('detailProcessingTime').textContent = log.processing_time !== undefined ? `${log.processing_time} seconds` : 'N/A';
        
        const riskLevelSpan = document.getElementById('detailRiskLevel');
        riskLevelSpan.textContent = log.risk_level || 'N/A';
        riskLevelSpan.className = 'detail-value';
        const riskVal = (log.risk_level || '').toUpperCase();
        if (riskVal.includes('LOW')) riskLevelSpan.style.color = '#10b981';
        else if (riskVal.includes('MEDIUM')) riskLevelSpan.style.color = '#f59e0b';
        else if (riskVal.includes('HIGH')) riskLevelSpan.style.color = '#ef4444';
        
        document.getElementById('detailRiskScore').textContent = log.risk_score !== undefined ? log.risk_score : 'N/A';
        document.getElementById('detailSummaryStatus').textContent = log.ai_summary_status || 'N/A';
        
        const statusSpan = document.getElementById('detailAnalysisStatus');
        statusSpan.textContent = log.status || 'N/A';
        statusSpan.className = 'detail-value';
        if ((log.status || '').toUpperCase() === 'SUCCESS') statusSpan.style.color = '#10b981';
        else statusSpan.style.color = '#ef4444';
        
        // Render Categories
        const catList = document.getElementById('detailCategoriesList');
        catList.innerHTML = '';
        if (log.categories_with_counts && Object.keys(log.categories_with_counts).length > 0) {
            for (const [cat, count] of Object.entries(log.categories_with_counts)) {
                const badge = document.createElement('span');
                badge.className = 'detail-category-badge';
                badge.textContent = `${cat} (${count})`;
                catList.appendChild(badge);
            }
        } else {
            catList.textContent = 'None';
        }
        
        // Render Compliance Frameworks
        const compList = document.getElementById('detailComplianceList');
        compList.innerHTML = '';
        if (log.compliance_frameworks && log.compliance_frameworks.length > 0) {
            log.compliance_frameworks.forEach(comp => {
                const badge = document.createElement('span');
                badge.className = 'detail-compliance-badge';
                badge.textContent = comp;
                compList.appendChild(badge);
            });
        } else {
            compList.textContent = 'None';
        }
        
        detailsModal.removeAttribute('hidden');
    }

    // Modal close hooks
    closeModalBtn.addEventListener('click', () => {
        detailsModal.setAttribute('hidden', '');
    });

    window.addEventListener('click', (e) => {
        if (e.target === detailsModal) {
            detailsModal.setAttribute('hidden', '');
        }
    });

    // Add search and filter action handlers
    auditSearchInput.addEventListener('input', filterAndRenderLogs);
    filterRisk.addEventListener('change', filterAndRenderLogs);
    filterStatus.addEventListener('change', filterAndRenderLogs);
    filterType.addEventListener('change', filterAndRenderLogs);

    // Setup headers sort bindings
    const sortHeaders = document.querySelectorAll('#auditTable th[data-sort]');
    sortHeaders.forEach(th => {
        th.addEventListener('click', () => {
            const column = th.getAttribute('data-sort');
            if (currentSortColumn === column) {
                currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                currentSortColumn = column;
                currentSortDirection = 'asc';
            }
            
            // Update UI Icons
            sortHeaders.forEach(h => {
                const icon = h.querySelector('i');
                if (icon) icon.remove();
            });
            
            const iconClass = currentSortDirection === 'asc' ? 'fa-sort-up' : 'fa-sort-down';
            th.insertAdjacentHTML('beforeend', ` <i class="fa-solid ${iconClass}"></i>`);
            
            filterAndRenderLogs();
        });
    });
});

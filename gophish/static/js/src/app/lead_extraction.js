/**
 * Lead Extraction Module for GoPhish
 * Handles IMAP connection testing, lead extraction, and import to groups
 */

// Global state
var currentSmtpId = null;
var currentJobId = null;
var extractionPollInterval = null;
var selectedLeads = [];
var allLeads = [];
var leadsPage = 0;
var leadsPerPage = 50;

/**
 * Test IMAP Connection
 */
function testIMAPConnection() {
    var smtpId = getCurrentSmtpId();
    var statusDiv = $('#imap_status');
    
    // Get IMAP settings from form
    var imapData = {
        imap_host: $('#imap_host').val(),
        imap_port: parseInt($('#imap_port').val()) || 993,
        imap_username: $('#imap_username').val(),
        imap_password: $('#imap_password').val(),
        imap_tls: $('#imap_tls').is(':checked'),
        imap_ignore_cert_errors: $('#imap_ignore_cert_errors').is(':checked')
    };
    
    // Validate
    if (!imapData.imap_host) {
        statusDiv.html('<div class="alert alert-warning"><i class="fa fa-exclamation-triangle"></i> Please enter IMAP host</div>');
        return;
    }
    
    statusDiv.html('<div class="alert alert-info"><i class="fa fa-spinner fa-spin"></i> Testing connection...</div>');
    
    // If profile is saved, use the API endpoint
    if (smtpId && smtpId > 0) {
        // First save the profile, then test
        api.SMTPId.put(getProfileData())
            .success(function(smtp) {
                testIMAPConnectionAPI(smtpId, statusDiv);
            })
            .error(function(response) {
                statusDiv.html('<div class="alert alert-danger"><i class="fa fa-times"></i> Save profile first: ' + response.responseJSON.message + '</div>');
            });
    } else {
        statusDiv.html('<div class="alert alert-warning"><i class="fa fa-exclamation-triangle"></i> Please save the profile first before testing IMAP connection</div>');
    }
}

/**
 * Test IMAP Connection via API
 */
function testIMAPConnectionAPI(smtpId, statusDiv) {
    $.ajax({
        url: '/api/smtp/' + smtpId + '/test-imap',
        method: 'POST',
        contentType: 'application/json',
        success: function(response) {
            statusDiv.html('<div class="alert alert-success"><i class="fa fa-check"></i> IMAP connection successful!</div>');
            $('#extractLeadsBtn').prop('disabled', false);
        },
        error: function(xhr) {
            var msg = 'Connection failed';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                msg = xhr.responseJSON.message;
            }
            statusDiv.html('<div class="alert alert-danger"><i class="fa fa-times"></i> ' + msg + '</div>');
            $('#extractLeadsBtn').prop('disabled', true);
        }
    });
}

/**
 * Get current SMTP profile ID
 */
function getCurrentSmtpId() {
    // This should be set when editing a profile
    return currentSmtpId || window.currentProfileId || null;
}

/**
 * Get profile data from form
 */
function getProfileData() {
    return {
        id: getCurrentSmtpId(),
        name: $('#name').val(),
        interface_type: 'SMTP',
        from_address: $('#from').val(),
        host: $('#host').val(),
        username: $('#username').val(),
        password: $('#password').val(),
        ignore_cert_errors: $('#ignore_cert_errors').is(':checked'),
        imap_host: $('#imap_host').val(),
        imap_port: parseInt($('#imap_port').val()) || 993,
        imap_username: $('#imap_username').val(),
        imap_password: $('#imap_password').val(),
        imap_tls: $('#imap_tls').is(':checked'),
        imap_ignore_cert_errors: $('#imap_ignore_cert_errors').is(':checked'),
        headers: getHeaders()
    };
}

/**
 * Get headers from table
 */
function getHeaders() {
    var headers = [];
    $('#headersTable tbody tr').each(function() {
        var key = $(this).find('td:eq(0)').text();
        var value = $(this).find('td:eq(1)').text();
        if (key && value) {
            headers.push({ key: key, value: value });
        }
    });
    return headers;
}

/**
 * Open Extract Leads Modal
 */
function openExtractLeadsModal() {
    var smtpId = getCurrentSmtpId();
    if (!smtpId) {
        alert('Please save the profile first');
        return;
    }
    
    currentSmtpId = smtpId;
    
    // Reset modal state
    $('#extractionSettings').show();
    $('#extractionProgress').hide();
    $('#extractedLeadsPanel').hide();
    $('#startExtractionBtn').show();
    $('#importLeadsBtn').hide();
    
    // Load folders
    loadIMAPFolders(smtpId);
    
    // Show modal
    $('#extractLeadsModal').modal('show');
}

/**
 * Load IMAP Folders
 */
function loadIMAPFolders(smtpId) {
    var folderList = $('#folderList');
    folderList.html('<div class="text-center"><i class="fa fa-spinner fa-spin"></i> Loading folders...</div>');
    
    $.ajax({
        url: '/api/smtp/' + smtpId + '/imap-folders',
        method: 'GET',
        success: function(response) {
            var folders = response.folders || [];
            var html = '';
            
            // Default selections
            var defaultFolders = ['[Gmail]/All Mail', 'INBOX', '[Gmail]/Sent Mail', 'Sent', 'Sent Items'];
            
            folders.forEach(function(folder) {
                var checked = defaultFolders.some(function(df) {
                    return folder.toLowerCase().indexOf(df.toLowerCase()) !== -1;
                }) ? 'checked' : '';
                
                html += '<div class="checkbox">';
                html += '<label>';
                html += '<input type="checkbox" name="folder" value="' + escapeHtml(folder) + '" ' + checked + '>';
                html += ' <i class="fa fa-folder-o"></i> ' + escapeHtml(folder);
                html += '</label>';
                html += '</div>';
            });
            
            if (html === '') {
                html = '<div class="alert alert-warning">No folders found</div>';
            }
            
            folderList.html(html);
        },
        error: function(xhr) {
            var msg = 'Failed to load folders';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                msg = xhr.responseJSON.message;
            }
            folderList.html('<div class="alert alert-danger"><i class="fa fa-times"></i> ' + msg + '</div>');
        }
    });
}

/**
 * Start Lead Extraction
 */
function startExtraction() {
    var smtpId = currentSmtpId;
    if (!smtpId) {
        alert('No profile selected');
        return;
    }
    
    // Get selected folders
    var folders = [];
    $('input[name="folder"]:checked').each(function() {
        folders.push($(this).val());
    });
    
    if (folders.length === 0) {
        alert('Please select at least one folder');
        return;
    }
    
    var daysBack = parseInt($('#daysBack').val()) || 160;
    
    // Show progress
    $('#extractionSettings').hide();
    $('#extractionProgress').show();
    $('#startExtractionBtn').hide();
    
    // Reset progress
    $('#extractionProgressBar').css('width', '0%').text('0%');
    $('#emailsProcessed').text('0');
    $('#leadsFound').text('0');
    $('#extractionStatus').text('Starting...');
    
    // Start extraction
    $.ajax({
        url: '/api/smtp/' + smtpId + '/extract-leads',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            folders: folders,
            days_back: daysBack
        }),
        success: function(response) {
            currentJobId = response.job_id;
            $('#extractionStatus').text('Running');
            
            // Start polling for progress
            startProgressPolling(currentJobId);
        },
        error: function(xhr) {
            var msg = 'Failed to start extraction';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                msg = xhr.responseJSON.message;
            }
            $('#extractionStatus').text('Failed');
            alert(msg);
        }
    });
}

/**
 * Start polling for extraction progress
 */
function startProgressPolling(jobId) {
    if (extractionPollInterval) {
        clearInterval(extractionPollInterval);
    }
    
    extractionPollInterval = setInterval(function() {
        $.ajax({
            url: '/api/leads/jobs/' + jobId,
            method: 'GET',
            success: function(job) {
                updateProgressUI(job);
                
                if (job.status === 'completed' || job.status === 'failed') {
                    clearInterval(extractionPollInterval);
                    extractionPollInterval = null;
                    
                    if (job.status === 'completed') {
                        onExtractionComplete();
                    }
                }
            },
            error: function() {
                // Continue polling
            }
        });
    }, 2000); // Poll every 2 seconds
}

/**
 * Update progress UI
 */
function updateProgressUI(job) {
    var total = job.total_emails || 1;
    var processed = job.processed_emails || 0;
    var leads = job.leads_found || 0;
    var percent = Math.round((processed / total) * 100);
    
    $('#extractionProgressBar').css('width', percent + '%').text(percent + '%');
    $('#emailsProcessed').text(processed + ' / ' + total);
    $('#leadsFound').text(leads);
    $('#extractionStatus').text(job.status.charAt(0).toUpperCase() + job.status.slice(1));
    
    if (job.status === 'completed') {
        $('#extractionProgressBar').removeClass('active').addClass('progress-bar-success');
    } else if (job.status === 'failed') {
        $('#extractionProgressBar').removeClass('active').addClass('progress-bar-danger');
    }
}

/**
 * Called when extraction is complete
 */
function onExtractionComplete() {
    // Load extracted leads
    loadExtractedLeads();
    
    // Show leads panel
    $('#extractedLeadsPanel').show();
    $('#importLeadsBtn').show();
}

/**
 * Load extracted leads
 */
function loadExtractedLeads() {
    leadsPage = 0;
    allLeads = [];
    
    $.ajax({
        url: '/api/leads/',
        method: 'GET',
        data: {
            smtp_id: currentSmtpId,
            page: leadsPage,
            per_page: leadsPerPage
        },
        success: function(response) {
            allLeads = response.leads || [];
            renderLeadsTable();
            
            if (response.total > allLeads.length) {
                $('#leadsLoadMore').show();
            } else {
                $('#leadsLoadMore').hide();
            }
        },
        error: function() {
            $('#extractedLeadsTable tbody').html('<tr><td colspan="5" class="text-center text-danger">Failed to load leads</td></tr>');
        }
    });
}

/**
 * Render leads table
 */
function renderLeadsTable() {
    var tbody = $('#extractedLeadsTable tbody');
    var html = '';
    
    allLeads.forEach(function(lead) {
        html += '<tr data-id="' + lead.id + '">';
        html += '<td><input type="checkbox" class="lead-checkbox" value="' + lead.id + '"></td>';
        html += '<td>' + escapeHtml(lead.email) + '</td>';
        html += '<td>' + escapeHtml(lead.name || '-') + '</td>';
        html += '<td><span class="label label-' + getSourceLabel(lead.source) + '">' + escapeHtml(lead.source) + '</span></td>';
        html += '<td>' + formatDate(lead.created_at) + '</td>';
        html += '</tr>';
    });
    
    if (html === '') {
        html = '<tr><td colspan="5" class="text-center">No leads found</td></tr>';
    }
    
    tbody.html(html);
    
    // Update select all checkbox
    $('#selectAllLeads').prop('checked', false);
}

/**
 * Get source label class
 */
function getSourceLabel(source) {
    switch (source) {
        case 'inbox': return 'primary';
        case 'sent': return 'success';
        case 'all_mail': return 'info';
        default: return 'default';
    }
}

/**
 * Format date
 */
function formatDate(dateStr) {
    if (!dateStr) return '-';
    var date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

/**
 * Load more leads
 */
function loadMoreLeads() {
    leadsPage++;
    
    $.ajax({
        url: '/api/leads/',
        method: 'GET',
        data: {
            smtp_id: currentSmtpId,
            page: leadsPage,
            per_page: leadsPerPage
        },
        success: function(response) {
            var newLeads = response.leads || [];
            allLeads = allLeads.concat(newLeads);
            renderLeadsTable();
            
            if (response.total <= allLeads.length) {
                $('#leadsLoadMore').hide();
            }
        }
    });
}

/**
 * Select all leads checkbox handler
 */
$(document).on('change', '#selectAllLeads', function() {
    var checked = $(this).is(':checked');
    $('.lead-checkbox').prop('checked', checked);
    updateSelectedCount();
});

/**
 * Individual lead checkbox handler
 */
$(document).on('change', '.lead-checkbox', function() {
    updateSelectedCount();
});

/**
 * Update selected leads count
 */
function updateSelectedCount() {
    var count = $('.lead-checkbox:checked').length;
    $('#selectedLeadsCount').text(count);
}

/**
 * Open import modal
 */
function openImportModal() {
    var selectedCount = $('.lead-checkbox:checked').length;
    if (selectedCount === 0) {
        alert('Please select at least one lead to import');
        return;
    }
    
    $('#selectedLeadsCount').text(selectedCount);
    
    // Load groups
    loadGroups();
    
    $('#importLeadsModal').modal('show');
}

/**
 * Load groups for import
 */
function loadGroups() {
    $.ajax({
        url: '/api/groups/',
        method: 'GET',
        success: function(groups) {
            var select = $('#targetGroup');
            select.empty();
            select.append('<option value="">-- Select a group --</option>');
            
            groups.forEach(function(group) {
                select.append('<option value="' + group.id + '">' + escapeHtml(group.name) + '</option>');
            });
        },
        error: function() {
            $('#targetGroup').html('<option value="">Failed to load groups</option>');
        }
    });
}

/**
 * Toggle import type (existing vs new group)
 */
function toggleImportType() {
    var importType = $('input[name="importType"]:checked').val();
    if (importType === 'existing') {
        $('#existingGroupSelect').show();
        $('#newGroupInput').hide();
    } else {
        $('#existingGroupSelect').hide();
        $('#newGroupInput').show();
    }
}

/**
 * Import leads to group
 */
function importLeadsToGroup() {
    var importType = $('input[name="importType"]:checked').val();
    var groupId = null;
    var groupName = null;
    
    if (importType === 'existing') {
        groupId = $('#targetGroup').val();
        if (!groupId) {
            alert('Please select a group');
            return;
        }
    } else {
        groupName = $('#newGroupName').val().trim();
        if (!groupName) {
            alert('Please enter a group name');
            return;
        }
    }
    
    // Get selected lead IDs
    var leadIds = [];
    $('.lead-checkbox:checked').each(function() {
        leadIds.push(parseInt($(this).val()));
    });
    
    if (leadIds.length === 0) {
        alert('No leads selected');
        return;
    }
    
    var data = {
        lead_ids: leadIds,
        merge: $('#mergeExisting').is(':checked')
    };
    
    if (groupId) {
        data.group_id = parseInt(groupId);
    } else {
        data.group_name = groupName;
    }
    
    $.ajax({
        url: '/api/leads/import',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(data),
        success: function(response) {
            alert('Successfully imported ' + response.imported + ' leads to group!');
            $('#importLeadsModal').modal('hide');
            
            // Refresh leads table to show updated status
            loadExtractedLeads();
        },
        error: function(xhr) {
            var msg = 'Failed to import leads';
            if (xhr.responseJSON && xhr.responseJSON.message) {
                msg = xhr.responseJSON.message;
            }
            alert(msg);
        }
    });
}

/**
 * Escape HTML
 */
function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

/**
 * Initialize when document is ready
 */
$(document).ready(function() {
    // Initialize tooltips
    $('[data-toggle="tooltip"]').tooltip();
    
    // Auto-detect IMAP settings based on email domain
    $('#username, #from').on('blur', function() {
        autoDetectIMAPSettings();
    });
});

/**
 * Auto-detect IMAP settings based on email
 */
function autoDetectIMAPSettings() {
    var email = $('#username').val() || $('#from').val();
    if (!email) return;
    
    // Extract domain
    var match = email.match(/@([^>]+)/);
    if (!match) return;
    
    var domain = match[1].toLowerCase().trim();
    
    // Only auto-fill if IMAP host is empty
    if ($('#imap_host').val()) return;
    
    // Common IMAP servers
    var imapServers = {
        'gmail.com': 'imap.gmail.com',
        'googlemail.com': 'imap.gmail.com',
        'outlook.com': 'outlook.office365.com',
        'hotmail.com': 'outlook.office365.com',
        'live.com': 'outlook.office365.com',
        'msn.com': 'outlook.office365.com',
        'yahoo.com': 'imap.mail.yahoo.com',
        'icloud.com': 'imap.mail.me.com',
        'me.com': 'imap.mail.me.com',
        'aol.com': 'imap.aol.com'
    };
    
    if (imapServers[domain]) {
        $('#imap_host').val(imapServers[domain]);
        $('#imap_port').val(993);
        $('#imap_tls').prop('checked', true);
    }
}

// Export functions for global access
window.testIMAPConnection = testIMAPConnection;
window.openExtractLeadsModal = openExtractLeadsModal;
window.startExtraction = startExtraction;
window.loadMoreLeads = loadMoreLeads;
window.openImportModal = openImportModal;
window.toggleImportType = toggleImportType;
window.importLeadsToGroup = importLeadsToGroup;

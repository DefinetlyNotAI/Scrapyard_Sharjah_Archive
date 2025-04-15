// noinspection JSUnresolvedReference,DuplicatedCode

document.getElementById("executeQuery").addEventListener("click", async () => {
    const query = document.getElementById("queryInput").value.trim();
    if (!query) {
        Swal.fire({
            icon: 'warning',
            title: 'Warning',
            text: 'Please enter a query.',
        });
        return;
    }

    const response = await fetch("/api/executeQuery", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({query})
    });

    const result = await response.json();
    const resultContainer = document.getElementById("queryResult");
    resultContainer.innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>`;
});

document.addEventListener("DOMContentLoaded", () => {
    const tableSelect = document.getElementById("tableSelect");
    const dataTable = document.getElementById("dataTable").querySelector("tbody");
    const totalRecords = document.getElementById("totalRecords");
    const dbSize = document.getElementById("dbSize");
    const activeConnections = document.getElementById("activeConnections");

    // Fetch table data
    fetch('/api/get/tables')
        .then(response => response.json())
        .then(data => {
            // Populate table dropdown
            data.forEach((table) => {
                const option = document.createElement('option');
                option.value = table;
                option.textContent = table;
                tableSelect.appendChild(option);

                // Populate table rows
                const row = document.createElement('tr');
                row.innerHTML = `
                        <td>${table}</td>
                        <td>
                            <button class="btn btn-danger delete-item" data-row-id="${table}" onclick="deleteTable('${table}')">Delete</button>
                        </td>
                    `;
                dataTable.appendChild(row);
            });

            totalRecords.textContent = data.length;
            fetch('/api/get/size')
                .then(response => response.json())
                .then(data => {
                    dbSize.textContent = data.size;
                    return fetch('/api/get/activeConnections');
                })
                .then(response => response.json())
                .then(data => {
                    activeConnections.textContent = data.activeConnections;
                })
                .catch(error => {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: 'Error fetching data: ' + error,
                    });
                    console.error("Error fetching data:", error);
                });
        })
        .catch(error => {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Error fetching tables: ' + error,
            });
            console.error("Error fetching tables:", error);
        });
});

function deleteTable(tableName) {
    fetch(`/api/delete/tables/${tableName}`, { method: "DELETE" })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                Swal.fire({
                    icon: 'success',
                    title: 'Success',
                    text: data.message,
                });
                // Refresh table data or perform any other necessary actions
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: 'Failed to delete table: ' + data.error,
                });
            }
        });
}

document.addEventListener("click", (e) => {
    if (e.target.classList.contains("delete-item")) {
        const rowId = e.target.dataset.rowId;
        const tableName = document.getElementById("tableSelect").value;

        if (rowId && tableName) {
            fetch(`/api/delete/tables/${tableName}/${rowId}`, {method: "DELETE"})
                .then(response => response.json())
                .then(data => {
                    if (data.message) {
                        Swal.fire({
                            icon: 'success',
                            title: 'Success',
                            text: data.message,
                        });
                        fetchTableData(tableName); // Refresh table data
                    } else {
                        Swal.fire({
                            icon: 'error',
                            title: 'Error',
                            text: 'Failed to delete item: ' + data.error,
                        });
                    }
                });
        }
    }

    if (e.target.classList.contains("delete-table")) {
        const tableName = e.target.dataset.tableName;
        if (tableName) {
            fetch(`/api/delete/tables/${tableName}`, {method: "DELETE"})
                .then(response => response.json())
                .then(data => {
                    if (data.message) {
                        Swal.fire({
                            icon: 'success',
                            title: 'Success',
                            text: data.message,
                        });
                        fetchTables(); // Refresh table list
                    } else {
                        Swal.fire({
                            icon: 'error',
                            title: 'Error',
                            text: 'Failed to delete table: ' + data.error,
                        });
                    }
                });
        }
    }

    if (e.target.classList.contains("delete-team")) {
        const teamId = e.target.dataset.teamId;
        deleteTeam(teamId);
    }
});

function deleteTeam(id) {
    Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, delete it!'
    }).then((result) => {
        if (result.isConfirmed) {
            fetch(`/api/delete/database`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({team_id: id})
            })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        Swal.fire({
                            icon: 'error',
                            title: 'Error',
                            text: data.error,
                        });
                    } else {
                        Swal.fire({
                            icon: 'success',
                            title: 'Deleted!',
                            text: data.message,
                        });
                        location.reload(); // Refresh to show updated records
                    }
                })
                .catch(error => {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: 'Error deleting team: ' + error,
                    });
                    console.error("Error deleting team:", error);
                });
        }
    });
}

document.getElementById("searchInput").addEventListener("input", (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const rows = dataTable.querySelectorAll("tr");
    rows.forEach(row => {
        const cells = Array.from(row.querySelectorAll("td"));
        row.style.display = cells.some(cell => cell.textContent.toLowerCase().includes(searchTerm)) ? "" : "none";
    });
});

function updateConnectionStatus(apiStatus, dbStatus) {
    const statusEl = document.getElementById('connectionStatus');
    const dbStatusEl = document.getElementById('databaseStatus');
    const indicator = document.querySelector(".status-indicator");

    statusEl.textContent = apiStatus ? 'Database' : 'Database';
    statusEl.style.color = apiStatus ? 'var(--success)' : 'red';

    dbStatusEl.textContent = dbStatus ? ' Connected' : ' Disconnected';
    dbStatusEl.style.color = dbStatus ? 'var(--success)' : 'red';

    indicator.style.backgroundColor = apiStatus && dbStatus ? "green" : "red";
}

async function checkConnection() {
    try {
        const response = await fetch('/api/status', {method: 'GET'});
        const data = await response.json();

        const apiRunning = data.status === "API is running";
        const dbConnected = data.database_connected === true;

        updateConnectionStatus(apiRunning, dbConnected);
        return {apiRunning, dbConnected};
    } catch (error) {
        updateConnectionStatus(false, false);
        throw error;
    } finally {
        setTimeout(checkConnection, 10000); // Check every 10 seconds
    }
}

async function init() {
    try {
        await checkConnection();
    } catch (error) {
        Swal.fire({
            icon: 'error',
            title: 'Initialization failed',
            text: error.message,
        });
        console.error('Initialization failed:', error);
        updateConnectionStatus(false);
    }
}

document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
        document.querySelectorAll(".panel").forEach(panel => panel.classList.remove("active"));

        tab.classList.add("active");
        document.getElementById(`${tab.dataset.tab}-panel`).classList.add("active");
    });
});

tableSelect.addEventListener("change", async (e) => {
    const tableName = e.target.value;

    if (!tableName) return;

    try {
        // Fetch headers first
        const headersRes = await fetch(`/api/get/tables/headers/${tableName}`);
        const headers = await headersRes.json();

        // Generate table header
        const tableHeaders = headers.map(header => `<th>${header}</th>`).join("");
        dataTable.innerHTML = `
            <thead>
                <tr>
                    ${tableHeaders}
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <!-- Data will be populated here -->
            </tbody>
        `;

        // Fetch table data
        const dataRes = await fetch(`/api/get/tables/${tableName}`);
        const data = await dataRes.json();

        // Generate table rows
        const tbody = dataTable.querySelector("tbody");
        tbody.innerHTML = data.map(row => `
            <tr>
                ${row.map(cell => `<td>${cell}</td>`).join("")}
                <td><button class="btn btn-danger" onclick="deleteRow(${row[0]})">Delete</button></td>
            </tr>
        `).join("");

    } catch (error) {
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: 'Failed to load table data: ' + error,
        });
        console.error("Error fetching table data:", error);
    }
});


function deleteRow(rowId) {
    const tableName = document.getElementById("tableSelect").value;
    if (!tableName) {
        Swal.fire({
            icon: 'warning',
            title: 'Warning',
            text: 'Please select a table first.',
        });
        return;
    }

    fetch(`/api/delete/tables/${tableName}/${rowId}`, {method: "DELETE"})
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                Swal.fire({
                    icon: 'success',
                    title: 'Success',
                    text: data.message,
                });
                fetchTableData(tableName); // Refresh table data
            } else {
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: 'Failed to delete item: ' + data.error,
                });
            }
        })
        .catch(error => {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Error deleting row: ' + error,
            });
            console.error("Error deleting row:", error);
        });
}

async function populateTableDropdown() {
    const response = await fetch("/api/get/tables");
    const tables = await response.json();

    tableSelect.innerHTML = '<option value="">Select Table</option>';
    tables.forEach(table => {
        const option = document.createElement("option");
        option.value = table;
        option.text = table;
        tableSelect.appendChild(option);
    });
}

function fetchTables() {
    fetch('api/get/tables')
        .then(response => response.json())
        .then(tables => {
            const tableSelect = document.getElementById("tableSelect");
            tableSelect.innerHTML = '<option value="">Select Table</option>'; // Reset options
            tables.forEach(table => {
                tableSelect.innerHTML += `<option value="${table}">${table}</option>`;
            });
        })
        .catch(error => {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Error fetching tables: ' + error,
            });
            console.error("Error fetching tables:", error);
        });
}

function fetchTableData(tableName) {
    fetch(`/api/get/tables/${tableName}`)
        .then(response => response.json())
        .then(data => {
            const dataTable = document.getElementById("dataTable").querySelector("tbody");
            dataTable.innerHTML = data.map(row => `
                <tr>
                    ${row.map(cell => `<td>${cell}</td>`).join("")}
                    <td><button class="btn btn-danger" onclick="deleteRow(${row[0]})">Delete</button></td>
                </tr>
            `).join("");
        })
        .catch(error => {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: 'Error fetching table data: ' + error,
            });
            console.error("Error fetching table data:", error);
        });
}

document.addEventListener("DOMContentLoaded", async () => {
    await populateTableDropdown();
    await init();
});

document.getElementById('createBackup').addEventListener('click', function() {
    window.location.href = '/backup/db';
});

document.addEventListener('DOMContentLoaded', () => {
  const socket = io(SOCKET_URL);
  const savedColumnVisibility = JSON.parse(localStorage.getItem('columnVisibility')) || {};
  let blockHeights = [];

  const table = new Tabulator('#mining-table', {
    index: 'pool_name',
    layout: 'fitColumns',
    movableColumns: true,
    resizableColumns: true,
    columns: getTableColumns(),
    initialSort: [{ column: 'coinbase_output_value', dir: 'desc' }],
  });

  table.on('tableBuilt', () => {
    applyColumnVisibility();
    createColumnToggles();
  });

  const liveTab = document.getElementById('live-tab');
  const historicalTab = document.getElementById('historical-tab');
  const historicalSelector = document.getElementById('historical-selector');
  const historicalSelect = document.getElementById('historical-select');

  liveTab.addEventListener('click', () => {
    toggleTab(liveTab, historicalTab);
    historicalSelector.style.display = 'none';
    socket.connect();
    table.clearData();
  });

  socket.on('mining_data', async (data) => {
    await updateTableData(data);
    updateBlockHeights(data.height);
  });

  function getTableColumns() {
    return [
      {
        title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/pool_name.md" target="_blank"><i class="fas fa-question-circle"></i></a> Pool Name',
        field: 'pool_name',
        width: 130,
      },
      {
        title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/timestamp.md" target="_blank"><i class="fas fa-question-circle"></i></a> Timestamp',
        field: 'timestamp',
        sorter: function (a, b, aRow, bRow, column, dir, sorterParams) {
          const timestampA = new Date(a).getTime();
          const timestampB = new Date(b).getTime();
          return timestampA - timestampB;
        },
        formatter: formatTimestamp,
      },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/height.md" target="_blank"><i class="fas fa-question-circle"></i></a> Height', field: 'height' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/prev_block_hash.md" target="_blank"><i class="fas fa-question-circle"></i></a> Previous Block Hash', field: 'prev_block_hash' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/block_version.md" target="_blank"><i class="fas fa-question-circle"></i></a> Block Version', field: 'block_version' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/coinbase_raw.md" target="_blank"><i class="fas fa-question-circle"></i></a> Coinbase RAW', field: 'coinbase_raw' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/version.md" target="_blank"><i class="fas fa-question-circle"></i></a> Version', field: 'version' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/nbits.md" target="_blank"><i class="fas fa-question-circle"></i></a> Nbits', field: 'nbits' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/ntime.md" target="_blank"><i class="fas fa-question-circle"></i></a> Ntime', field: 'ntime', formatter: formatNtimeTimestamp },      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/coinbase_script_ascii.md" target="_blank"><i class="fas fa-question-circle"></i></a> Coinbase Script (ASCII)', field: 'coinbase_script_ascii' },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/clean_jobs.md" target="_blank"><i class="fas fa-question-circle"></i></a> Clean Jobs', field: 'clean_jobs' },
      {
        title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/first_transaction.md" target="_blank"><i class="fas fa-question-circle"></i></a> First Tx',
        field: 'first_transaction',
        formatter: function(cell, formatterParams, onRendered) {
          const value = cell.getValue();
          if (value !== 'empty block') {
            return `<a href="https://mempool.space/tx/${value}" target="_blank">${value}</a>`;
          } else {
            return value;
          }
        }
      },
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/fee_rate.md" target="_blank"><i class="fas fa-question-circle"></i></a> First Tx Fee Rate (sat/vB)', field: 'fee_rate' },
      ...getMerkleBranchColumns(),
      { title: '<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/coinbase_output_value.md" target="_blank"><i class="fas fa-question-circle"></i></a> Coinbase Output Value', field: 'coinbase_output_value' },
    ];
  }

  function formatTimestamp(cell) {
    const timestamp = cell.getValue();
    let date;
    if (typeof timestamp === 'object' && timestamp.$date) {
      date = new Date(timestamp.$date);
    } else if (typeof timestamp === 'string') {
      date = new Date(timestamp);
    } else {
      date = new Date(timestamp);
    }
    return `${padZero(date.getUTCHours())}:${padZero(date.getUTCMinutes())}:${padZero(date.getUTCSeconds())}`;
  }

  function formatNtimeTimestamp(cell) {
    const ntimeHex = cell.getValue();
    const ntimeInt = parseInt(ntimeHex, 16);
    const date = new Date(ntimeInt * 1000);
    return formatTimestamp({ getValue: () => date });
  }

  function padZero(value) {
    return value.toString().padStart(2, '0');
  }

  function getMerkleBranchColumns() {
    const merkleBranchColumns = [];
    for (let i = 0; i < 12; i++) {
      merkleBranchColumns.push({
        title: `<a href="https://github.com/bboerst/stratum-logger/blob/main/docs/merkle_branches.md" target="_blank"><i class="fas fa-question-circle"></i></a> Merkle Branch ${i}`,
        field: 'merkle_branches',
        formatter: merkleBranchFormatter(i),
      });
    }
    return merkleBranchColumns;
  }

  function merkleBranchFormatter(index) {
    return (cell) => {
      const merkleBranches = cell.getValue();
      const colors = cell.getRow().getData().merkle_branch_colors;
      if (!merkleBranches) return '';
      const value = merkleBranches[index] || '';
      cell.getElement().style.backgroundColor = colors[index] || 'white';
      return `${value}`;
    };
  }

  async function updateTableData(data) {
    const currentSorters = table.getSorters();

    // Replace empty merkle_branches with an empty string
    const modifiedData = (Array.isArray(data) ? data : [data]).map(row => {
      if (row.merkle_branches) {
        row.merkle_branches = row.merkle_branches.map(branch => branch || '');
      }
      return row;
    });

    table.updateOrAddData(modifiedData);
    if (currentSorters.length > 0) {
      table.setSort(currentSorters);
    }
  }

  function createColumnToggles() {
    const columnToggles = document.getElementById('column-toggles');
    columnToggles.innerHTML = '';
    table.getColumns().forEach((column) => {
      const field = column.getField();
      const toggleDiv = document.createElement('div');
      const toggleLabel = document.createElement('label');
      const toggleCheckbox = document.createElement('input');
      toggleCheckbox.type = 'checkbox';
      toggleCheckbox.checked = savedColumnVisibility[field] !== false;
      toggleCheckbox.addEventListener('change', () => {
        const isVisible = toggleCheckbox.checked;
        isVisible ? table.showColumn(field) : table.hideColumn(field);
        savedColumnVisibility[field] = isVisible;
        localStorage.setItem('columnVisibility', JSON.stringify(savedColumnVisibility));
      });
      toggleLabel.appendChild(toggleCheckbox);
      toggleLabel.appendChild(document.createTextNode(column.getDefinition().title));
      toggleDiv.appendChild(toggleLabel);
      columnToggles.appendChild(toggleDiv);
    });
  }

  function applyColumnVisibility() {
    Object.entries(savedColumnVisibility).forEach(([field, isVisible]) => {
      if (!isVisible) table.hideColumn(field);
    });
  }

  function toggleTab(activeTab, inactiveTab) {
    activeTab.classList.add('active');
    inactiveTab.classList.remove('active');
  }

  function updateBlockHeights(blockHeight) {
    if (!blockHeights.includes(blockHeight)) {
      blockHeights.push(blockHeight);
      populateBlockHeightsDropdown();
    }
  }

  function populateBlockHeightsDropdown() {
    const latestBlockHeight = Math.max(...blockHeights);
    const startBlockHeight = Math.max(0, latestBlockHeight - 100);
    historicalSelect.innerHTML = '';
    for (let i = latestBlockHeight; i >= startBlockHeight; i--) {
      const option = document.createElement('option');
      option.value = i;
      option.textContent = i;
      historicalSelect.appendChild(option);
    }
  }

  const settingsIcon = document.querySelector('.settings-icon');
  const configSection = document.getElementById('config-section');
  settingsIcon.addEventListener('click', () => {
    configSection.classList.toggle('show');
    createColumnToggles();
  });

  document.addEventListener('click', (event) => {
    const { target } = event;
    if (!configSection.contains(target) && !settingsIcon.contains(target)) {
      configSection.classList.remove('show');
    }
  });
});
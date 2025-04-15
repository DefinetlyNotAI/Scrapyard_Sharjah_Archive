async function markAsPaid(receiptId) {
    const response = await fetch('{{ url_for("update_stock") }}', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ receipt_id: receiptId })
    });
    if (response.ok) {
        alert('Receipt marked as paid.');
        location.reload();
    } else {
        alert('Failed to mark receipt as paid.');
    }
}

async function cancelReceipt(receiptId) {
    const response = await fetch('{{ url_for("cancel_receipt") }}', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ receipt_id: receiptId })
    });
    if (response.ok) {
        alert('Receipt canceled.');
        location.reload();
    } else {
        alert('Failed to cancel receipt.');
    }
}

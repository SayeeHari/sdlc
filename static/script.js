 function showAuditeeFields() {
            let count = document.getElementById("auditee_count").value;
            let container = document.querySelector(".ds-auditee-names");
            container.innerHTML = "";
            for (let i = 1; i <= count; i++) {
                container.innerHTML += `<input type="text" name="auditee_name_${i}" placeholder="Auditee Name ${i}" required>`;
            }
        }
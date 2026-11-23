// Synthetic vulnerable JS fixture (never executed; scanner input only).
const { exec } = require("child_process");

function showComment(text) {
  document.getElementById("comments").innerHTML = text;
}

function rotateLogs(name) {
  exec(`logrotate --force /etc/logrotate.d/${name}`);
}

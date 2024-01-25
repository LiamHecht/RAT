function toggleSettings() {
    var colorPickerContainer = document.getElementById("colorPickerContainer");
    colorPickerContainer.style.display = (colorPickerContainer.style.display === "none") ? "block" : "none";
}

function changeColor(color) {
    document.body.style.backgroundColor = color;
}

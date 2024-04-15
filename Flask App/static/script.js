function showContent(id) {
    // Hide all content divs
    document.getElementById('email-upload').style.display = 'none';
    document.getElementById('attachment-scanner').style.display = 'none';
    document.getElementById('url-scanner').style.display = 'none';

    // Remove current-tab class from all buttons
    var buttons = document.querySelectorAll('#mini-nav button');
    for (var i = 0; i < buttons.length; i++) {
        buttons[i].classList.remove('current-tab');
    }

    // Add current-tab class to clicked button
    document.querySelector('#mini-nav button[onclick="showContent(\'' + id + '\')"]').classList.add('current-tab');

    // Show the selected content div
    document.getElementById(id).style.display = 'block';

    // Clear scan results when switching mini-nav bar
    document.getElementById("scan-results").style.display = 'none';
}

var slider = document.getElementById("rating");
    var output = document.getElementById("ratingValue");
    slider.oninput = function() {
        var value = this.value;
        var text = value + " (";
        if (value <= 2) text += "Not Accurate)";
        else if (value <= 4) text += "Accurate)";
        else text += "Very Accurate)";
        output.innerHTML = text;
}



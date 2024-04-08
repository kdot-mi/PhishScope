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
}


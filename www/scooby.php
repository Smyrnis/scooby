<?php
// scooby.php
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>scooby ASCII</title>
 <link rel="icon" href="assets/favicon.ico" type="image/x-icon">
<style>
    body {
        background-color: black;
        color: blue;
        font-family: monospace;
        white-space: pre;
        align-items: center;
        height: 100vh;
    }
    #ascii-art {
        cursor: pointer;
        font-size: 28px;
        line-height: 32px;
        transition: all 0.3s ease-in-out;
    }
    a {
        text-decoration: none;
        color: blue;
        text-align:center;
    }
    a:hover #ascii-art {
        color: #ffcc00;
    }
    h1{
        display: flex;
        justify-content:center;
        font-size: 16px;
        color: #ffcc00;
    }
    footer {
    margin-top: 40px;
    font-size: 1rem;
    color: #888;
    border-top: 1px solid #333;
    padding-top: 20px;
    text-align:center;
}

</style>
</head>
<body>
<h1>Try petting the dog , but do not click it , it goes back in time!</h1>
<a href="index.html">
<pre id="ascii-art">
 / \__
    (    @\___
    /         O
   /   (_____/
  /_____/   U
</pre>
</a>

<script>
const art = document.getElementById('ascii-art');

const asciiFrames = [
`   / \\__
    (    @\\___
    /         O
   /   (_____/
  /_____/   U`,
`   / \\__
    (   -@\\___
    /         o
   /   (_____/
  /_____/   U`
];

let currentFrame = 0;
let interval;

art.addEventListener('mouseenter', () => {
    interval = setInterval(() => {
        currentFrame = (currentFrame + 1) % asciiFrames.length;
        art.textContent = asciiFrames[currentFrame];
    }, 300);
});

art.addEventListener('mouseleave', () => {
    clearInterval(interval);
    art.textContent = asciiFrames[0];
});
</script>
<footer>
    <p>Delete and make your own , have fun !</p>
</footer>
</body>
</html>

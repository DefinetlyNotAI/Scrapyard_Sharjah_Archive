// noinspection JSUnresolvedReference

function initParticleBackground() {
    const canvas = document.createElement("canvas")
    canvas.id = "particle-background"
    canvas.style.position = "fixed"
    canvas.style.top = "0"
    canvas.style.left = "0"
    canvas.style.width = "100%"
    canvas.style.height = "100%"
    canvas.style.zIndex = "-1"
    canvas.style.opacity = "0.3"
    document.body.prepend(canvas)

    const ctx = canvas.getContext("2d")
    let particles = []
    const particleCount = 50

    // Resize canvas to match window size
    function resizeCanvas() {
        canvas.width = window.innerWidth
        canvas.height = window.innerHeight
    }

    // Create particles
    function createParticles() {
        particles = []
        for (let i = 0; i < particleCount; i++) {
            particles.push({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                radius: Math.random() * 3 + 1,
                color: "#6366f1",
                speedX: Math.random() * 0.5 - 0.25,
                speedY: Math.random() * 0.5 - 0.25,
            })
        }
    }

    // Draw particles
    function drawParticles() {
        ctx.clearRect(0, 0, canvas.width, canvas.height)

        particles.forEach((particle) => {
            ctx.beginPath()
            ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2)
            ctx.fillStyle = particle.color
            ctx.fill()

            // Update position
            particle.x += particle.speedX
            particle.y += particle.speedY

            // Bounce off edges
            if (particle.x < 0 || particle.x > canvas.width) {
                particle.speedX *= -1
            }

            if (particle.y < 0 || particle.y > canvas.height) {
                particle.speedY *= -1
            }
        })

        // Connect particles with lines if they're close enough
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x
                const dy = particles[i].y - particles[j].y
                const distance = Math.sqrt(dx * dx + dy * dy)

                if (distance < 100) {
                    ctx.beginPath()
                    ctx.strokeStyle = `rgba(99, 102, 241, ${0.2 - distance / 500})`
                    ctx.lineWidth = 1
                    ctx.moveTo(particles[i].x, particles[i].y)
                    ctx.lineTo(particles[j].x, particles[j].y)
                    ctx.stroke()
                }
            }
        }

        requestAnimationFrame(drawParticles)
    }

    // Initialize
    window.addEventListener("resize", resizeCanvas)
    resizeCanvas()
    createParticles()
    drawParticles()
}

// Confetti effect for successful operations
function showConfetti() {
    const canvas = document.createElement("canvas")
    canvas.id = "confetti-canvas"
    canvas.style.position = "fixed"
    canvas.style.top = "0"
    canvas.style.left = "0"
    canvas.style.width = "100%"
    canvas.style.height = "100%"
    canvas.style.pointerEvents = "none"
    canvas.style.zIndex = "9999"
    document.body.appendChild(canvas)

    const ctx = canvas.getContext("2d")
    canvas.width = window.innerWidth
    canvas.height = window.innerHeight

    const confettiCount = 150
    const confetti = []
    const colors = ["#6366f1", "#10b981", "#f59e0b", "#ef4444", "#3b82f6"]

    for (let i = 0; i < confettiCount; i++) {
        confetti.push({
            x: Math.random() * canvas.width,
            y: -20,
            size: Math.random() * 10 + 5,
            color: colors[Math.floor(Math.random() * colors.length)],
            speed: Math.random() * 3 + 2,
            angle: Math.random() * 6.28,
            rotation: Math.random() * 0.2 - 0.1,
            rotationSpeed: Math.random() * 0.01,
        })
    }

    function drawConfetti() {
        ctx.clearRect(0, 0, canvas.width, canvas.height)

        let stillActive = false

        confetti.forEach((c) => {
            if (c.y < canvas.height + 20) {
                stillActive = true

                ctx.save()
                ctx.translate(c.x, c.y)
                ctx.rotate(c.angle)
                ctx.fillStyle = c.color
                ctx.fillRect(-c.size / 2, -c.size / 2, c.size, c.size / 2)
                ctx.restore()

                c.y += c.speed
                c.angle += c.rotationSpeed
            }
        })

        if (stillActive) {
            requestAnimationFrame(drawConfetti)
        } else {
            document.body.removeChild(canvas)
        }
    }

    drawConfetti()
}

// Subtle hover effects for cards
function initCardHoverEffects() {
    const cards = document.querySelectorAll(".card")

    cards.forEach((card) => {
        card.addEventListener("mouseenter", () => {
            card.style.transform = "translateY(-5px)"
            card.style.boxShadow = "0 10px 15px -3px rgba(0, 0, 0, 0.3)"
            card.style.transition = "transform 0.3s ease, box-shadow 0.3s ease"
        })

        card.addEventListener("mouseleave", () => {
            card.style.transform = "translateY(0)"
            card.style.boxShadow = ""
        })
    })
}

// Theme toggle functionality
function initThemeToggle() {
    // Create toggle switch
    const themeToggleContainer = document.createElement("div")
    themeToggleContainer.className = "theme-toggle-container"
    themeToggleContainer.style.position = "fixed"
    themeToggleContainer.style.bottom = "20px"
    themeToggleContainer.style.right = "20px"
    themeToggleContainer.style.zIndex = "1000"
    themeToggleContainer.style.display = "flex"
    themeToggleContainer.style.alignItems = "center"
    themeToggleContainer.style.padding = "8px 12px"
    themeToggleContainer.style.backgroundColor = "rgba(30, 41, 59, 0.8)"
    themeToggleContainer.style.borderRadius = "20px"
    themeToggleContainer.style.boxShadow = "0 4px 6px -1px rgba(0, 0, 0, 0.1)"

    // Add moon and sun icons
    themeToggleContainer.innerHTML = `
        <i class="fas fa-moon" style="color: #94a3b8; margin-right: 8px;"></i>
        <label class="switch">
            <input type="checkbox" id="theme-toggle">
            <span class="slider round"></span>
        </label>
        <i class="fas fa-sun" style="color: #f59e0b; margin-left: 8px;"></i>
    `

    document.body.appendChild(themeToggleContainer)

    // Add CSS for toggle switch
    const style = document.createElement("style")
    style.textContent = `
        .switch {
            position: relative;
            display: inline-block;
            width: 40px;
            height: 20px;
        }
        
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #1e293b;
            transition: .4s;
        }
        
        .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 2px;
            bottom: 2px;
            background-color: white;
            transition: .4s;
        }
        
        input:checked + .slider {
            background-color: #6366f1;
        }
        
        input:checked + .slider:before {
            transform: translateX(20px);
        }
        
        .slider.round {
            border-radius: 20px;
        }
        
        .slider.round:before {
            border-radius: 50%;
        }
        
        /* Light mode styles */
        body.light-mode {
            background-color: #f1f5f9;
            color: #0f172a;
        }
        
        body.light-mode .card,
        body.light-mode .navbar,
        body.light-mode .stat-card {
            background-color: #ffffff;
            border-color: #e2e8f0;
        }
        
        body.light-mode .form-control {
            background-color: #f8fafc;
            border-color: #e2e8f0;
            color: #0f172a;
        }
        
        body.light-mode .card-title,
        body.light-mode .stat-value {
            color: #0f172a;
        }
        
        body.light-mode .text-muted,
        body.light-mode .form-label,
        body.light-mode .stat-title {
            color: #64748b;
        }
        
        body.light-mode .nav-link {
            color: #64748b;
        }
        
        body.light-mode .nav-link:hover,
        body.light-mode .nav-link.active {
            color: #6366f1;
        }
        
        body.light-mode .table th {
            background-color: #f8fafc;
            color: #64748b;
        }
        
        body.light-mode .table td {
            border-color: #e2e8f0;
        }
        
        body.light-mode .table tbody tr:hover {
            background-color: #f8fafc;
        }
        
        body.light-mode .table-striped tbody tr:nth-of-type(odd) {
            background-color: #f8fafc;
        }
    `

    document.head.appendChild(style)

    // Toggle theme
    const themeToggle = document.getElementById("theme-toggle")
    const currentTheme = localStorage.getItem("theme") || "dark"

    // Set initial theme
    document.body.classList.toggle("light-mode", currentTheme === "light")
    themeToggle.checked = currentTheme === "light"

    themeToggle.addEventListener("change", function () {
        if (this.checked) {
            document.body.classList.add("light-mode")
            localStorage.setItem("theme", "light")
        } else {
            document.body.classList.remove("light-mode")
            localStorage.setItem("theme", "dark")
        }
    })
}

// Keyboard shortcuts
function initKeyboardShortcuts() {
    const shortcuts = [
        {key: "u", description: "Go to Users", action: () => (window.location.href = "/admin/users")},
        {key: "l", description: "Go to Logs", action: () => (window.location.href = "/admin/logs")},
        {key: "d", description: "Go to Dashboard", action: () => (window.location.href = "/admin")},
        {key: "n", description: "Add New User", action: () => document.getElementById("newName").focus()},
        {key: "e", description: "Export Users", action: () => (window.location.href = "/admin/export-users")},
        {key: "?", description: "Show Keyboard Shortcuts", action: showShortcutsModal},
    ]

    function showShortcutsModal() {
        let shortcutsHTML = '<div class="shortcuts-list">'
        shortcuts.forEach((s) => {
            shortcutsHTML += `<div class="shortcut-item">
                <span class="shortcut-key">${s.key}</span>
                <span class="shortcut-description">${s.description}</span>
            </div>`
        })
        shortcutsHTML += "</div>"

        Swal.fire({
            title: "Keyboard Shortcuts",
            html: shortcutsHTML,
            confirmButtonText: "Got it!",
            confirmButtonColor: "#6366f1",
            customClass: {
                container: "shortcuts-modal",
            },
        })
    }

    // Add CSS for shortcuts modal
    const style = document.createElement("style")
    style.textContent = `
        .shortcuts-list {
            text-align: left;
            margin: 20px 0;
        }
        
        .shortcut-item {
            display: flex;
            margin-bottom: 10px;
            align-items: center;
        }
        
        .shortcut-key {
            display: inline-block;
            background-color: #1e293b;
            color: #f8fafc;
            border-radius: 4px;
            padding: 2px 8px;
            font-family: monospace;
            margin-right: 10px;
            min-width: 24px;
            text-align: center;
        }
        
        .shortcut-description {
            color: #64748b;
        }
        
        body.light-mode .shortcut-key {
            background-color: #e2e8f0;
            color: #0f172a;
        }
    `

    document.head.appendChild(style)

    // Listen for key presses
    document.addEventListener("keydown", (e) => {
        // Don't trigger shortcuts when typing in input fields
        if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
            return
        }

        const shortcut = shortcuts.find((s) => s.key === e.key.toLowerCase())
        if (shortcut) {
            e.preventDefault()
            shortcut.action()
        }
    })

    // Add keyboard shortcut hint
    const shortcutHint = document.createElement("div")
    shortcutHint.className = "shortcut-hint"
    shortcutHint.innerHTML = 'Press <span class="shortcut-key">?</span> for keyboard shortcuts'
    shortcutHint.style.position = "fixed"
    shortcutHint.style.bottom = "20px"
    shortcutHint.style.left = "20px"
    shortcutHint.style.fontSize = "12px"
    shortcutHint.style.color = "#94a3b8"
    shortcutHint.style.zIndex = "1000"

    document.body.appendChild(shortcutHint)
}

// Initialize all effects
document.addEventListener("DOMContentLoaded", () => {
    // Initialize particle background
    initParticleBackground()

    // Initialize card hover effects
    initCardHoverEffects()

    // Initialize theme toggle
    initThemeToggle()

    // Initialize keyboard shortcuts
    initKeyboardShortcuts()

    // Override success messages to show confetti
    const originalSwalFire = Swal.fire
    Swal.fire = function (...args) {
        if (args[0] && args[0].icon === "success") {
            showConfetti()
        }
        return originalSwalFire.apply(this, args)
    }
})


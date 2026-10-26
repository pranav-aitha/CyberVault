/**
 * Lightweight Canvas Confetti Engine
 */

const Confetti = (function () {
  let canvas = null;
  let ctx = null;
  let particles = [];
  let animationId = null;

  function init() {
    canvas = document.getElementById('confetti-canvas');
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = 'confetti-canvas';
      document.body.appendChild(canvas);
    }
    ctx = canvas.getContext('2d');
    resize();
    window.addEventListener('resize', resize);
  }

  function resize() {
    if (canvas) {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    }
  }

  function trigger(count = 60) {
    if (!canvas) init();

    const colors = ['#06b6d4', '#6366f1', '#10b981', '#f59e0b', '#ec4899', '#38bdf8'];
    const originX = canvas.width / 2;
    const originY = canvas.height * 0.45;

    for (let i = 0; i < count; i++) {
      const angle = Math.random() * Math.PI * 2;
      const velocity = Math.random() * 12 + 4;
      particles.push({
        x: originX,
        y: originY,
        vx: Math.cos(angle) * velocity,
        vy: Math.sin(angle) * velocity - 3,
        size: Math.random() * 7 + 4,
        color: colors[Math.floor(Math.random() * colors.length)],
        rotation: Math.random() * 360,
        rotationSpeed: (Math.random() - 0.5) * 12,
        gravity: 0.28,
        friction: 0.96,
        alpha: 1,
        decay: Math.random() * 0.015 + 0.012
      });
    }

    if (!animationId) {
      render();
    }
  }

  function render() {
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.vx *= p.friction;
      p.vy = p.vy * p.friction + p.gravity;
      p.x += p.vx;
      p.y += p.vy;
      p.rotation += p.rotationSpeed;
      p.alpha -= p.decay;

      if (p.alpha <= 0 || p.y > canvas.height) {
        particles.splice(i, 1);
        continue;
      }

      ctx.save();
      ctx.translate(p.x, p.y);
      ctx.rotate((p.rotation * Math.PI) / 180);
      ctx.globalAlpha = p.alpha;
      ctx.fillStyle = p.color;
      ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.7);
      ctx.restore();
    }

    if (particles.length > 0) {
      animationId = requestAnimationFrame(render);
    } else {
      animationId = null;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    }
  }

  return {
    init,
    trigger
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Confetti;
}

(function() {
  var canvas = document.getElementById('cosmos-canvas');
  var context = canvas && canvas.getContext('2d', {alpha: true});

  if (!canvas || !context) return;

  var motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
  var reducedMotion = motionPreference.matches;
  var frameId = 0;
  var resizeId = 0;
  var lastFrameTime = 0;
  var frameInterval = 1000 / 30;
  var width = 0;
  var height = 0;
  var pixelRatio = 1;
  var stars = [];
  var dust = [];
  var nebulae = [];
  var clusters = [];
  // Vary the cloud structure on load, while keeping it stable across resizes.
  var cloudSeed = Math.floor(Math.random() * 0x100000000);

  function createRandom(seed) {
    return function() {
      seed |= 0;
      seed = seed + 0x6d2b79f5 | 0;
      var value = Math.imul(seed ^ seed >>> 15, 1 | seed);
      value = value + Math.imul(value ^ value >>> 7, 61 | value) ^ value;
      return ((value ^ value >>> 14) >>> 0) / 4294967296;
    };
  }

  function color(colorValue, alpha) {
    return 'rgba(' + colorValue[0] + ', ' + colorValue[1] + ', ' + colorValue[2] + ', ' + alpha + ')';
  }

  function mixColor(from, to, amount) {
    return [
      Math.round(from[0] + (to[0] - from[0]) * amount),
      Math.round(from[1] + (to[1] - from[1]) * amount),
      Math.round(from[2] + (to[2] - from[2]) * amount)
    ];
  }

  function nebulaShift(cluster, time) {
    return 0.5 + Math.sin(time * 0.075 + cluster.phase) * 0.5;
  }

  function nebulaColor(cluster, time) {
    return mixColor(cluster.palette[0].primary, cluster.palette[1].primary, nebulaShift(cluster, time));
  }

  function noiseHash(x, y, seed) {
    var value = Math.imul(x, 374761393) + Math.imul(y, 668265263) + Math.imul(seed, 1442695041);
    value = Math.imul(value ^ value >>> 13, 1274126177);
    return ((value ^ value >>> 16) >>> 0) / 4294967295;
  }

  function smoothNoise(x, y, seed) {
    var x0 = Math.floor(x);
    var y0 = Math.floor(y);
    var xBlend = x - x0;
    var yBlend = y - y0;
    var topLeft = noiseHash(x0, y0, seed);
    var topRight = noiseHash(x0 + 1, y0, seed);
    var bottomLeft = noiseHash(x0, y0 + 1, seed);
    var bottomRight = noiseHash(x0 + 1, y0 + 1, seed);

    xBlend = xBlend * xBlend * (3 - 2 * xBlend);
    yBlend = yBlend * yBlend * (3 - 2 * yBlend);

    return (topLeft + (topRight - topLeft) * xBlend) * (1 - yBlend)
      + (bottomLeft + (bottomRight - bottomLeft) * xBlend) * yBlend;
  }

  function fractalNoise(x, y, seed, octaves) {
    var amplitude = 0.57;
    var frequency = 1;
    var total = 0;
    var normalization = 0;

    for (var octave = 0; octave < octaves; octave += 1) {
      total += smoothNoise(x * frequency, y * frequency, seed + octave * 1013) * amplitude;
      normalization += amplitude;
      frequency *= 2.03;
      amplitude *= 0.54;
    }

    return total / normalization;
  }

  function buildNebulaTexture(cluster, clusterIndex) {
    var texture = document.createElement('canvas');
    var tintedTexture = document.createElement('canvas');
    var textureWidth = 384;
    var textureHeight = 256;
    var textureContext;
    var tintedContext;
    var image;
    var pixels;
    var seed = (cloudSeed + clusterIndex * 7919) >>> 0;

    texture.width = textureWidth;
    texture.height = textureHeight;
    tintedTexture.width = textureWidth;
    tintedTexture.height = textureHeight;
    textureContext = texture.getContext('2d', {alpha: true});
    tintedContext = tintedTexture.getContext('2d', {alpha: true});
    if (!textureContext || !tintedContext) return {density: texture, tinted: texture, context: null, tintTick: -1};

    image = textureContext.createImageData(textureWidth, textureHeight);
    pixels = image.data;

    // Approximate a turbulent column-density field with domain-warped fBm,
    // ridged filaments, and a lognormal density remap.
    for (var y = 0; y < textureHeight; y += 1) {
      for (var x = 0; x < textureWidth; x += 1) {
        var normalizedX = (x / textureWidth - 0.5) * 3.5;
        var normalizedY = (y / textureHeight - 0.5) * 2.55;
        var warpX = fractalNoise(normalizedX * 0.72 + 11.3, normalizedY * 0.72 - 4.1, seed + 17, 3) - 0.5;
        var warpY = fractalNoise(normalizedX * 0.72 - 7.7, normalizedY * 0.72 + 8.4, seed + 37, 3) - 0.5;
        var warpedX = normalizedX + warpX * 1.45;
        var warpedY = normalizedY + warpY * 1.45;
        var broad = fractalNoise(warpedX * 0.82, warpedY * 0.82, seed, 5);
        var ridgedSource = fractalNoise(warpedX * 1.7 + 19.2, warpedY * 1.7 - 13.4, seed + 71, 4);
        var ridged = 1 - Math.abs(ridgedSource * 2 - 1);
        var detail = fractalNoise(warpedX * 3.8, warpedY * 3.8, seed + 149, 3);
        var spine = warpedY - Math.sin(warpedX * 1.35 + cluster.phase) * 0.34;
        var envelope = Math.exp(-(spine * spine * 0.72 + warpedX * warpedX * 0.12));
        var turbulence = broad * 0.54 + ridged * 0.34 + detail * 0.12;
        var logDensity = Math.exp((turbulence - 0.56) * 3.1);
        var density = Math.max(0, Math.min(1, (logDensity - 0.48) * 0.72)) * envelope;
        var absorption = Math.max(0, fractalNoise(warpedX * 1.25 - 28, warpedY * 1.25 + 16, seed + 211, 3) - 0.58) * 2.1;
        // Fade into an irregular oval well inside the texture's bounds.
        // A fade measured from the four edges exposes the rectangular sprite.
        var edgeX = x / (textureWidth - 1) * 2 - 1;
        var edgeY = y / (textureHeight - 1) * 2 - 1;
        var edgeRadius = Math.sqrt(edgeX * edgeX + edgeY * edgeY);
        var edgeNoise = smoothNoise(normalizedX * 1.4 + 6.7, normalizedY * 1.4 - 9.2, seed + 313);
        var edgeBoundary = 0.88 + (edgeNoise - 0.5) * 0.12;
        var edgeWindow = Math.max(0, Math.min(1, (edgeBoundary - edgeRadius) / 0.48));
        var alpha;
        var pixelIndex = (y * textureWidth + x) * 4;

        edgeWindow = edgeWindow * edgeWindow * (3 - 2 * edgeWindow);
        alpha = Math.pow(Math.max(0, density - absorption), 1.18) * edgeWindow;

        pixels[pixelIndex] = 255;
        pixels[pixelIndex + 1] = 255;
        pixels[pixelIndex + 2] = 255;
        pixels[pixelIndex + 3] = Math.round(alpha * 190);
      }
    }

    textureContext.putImageData(image, 0, 0);

    return {density: texture, tinted: tintedTexture, context: tintedContext, tintTick: -1};
  }

  function tintNebulaTexture(cluster, clusterIndex, time) {
    var nebula = nebulae[clusterIndex];
    var tintTick = Math.floor(time * 10);

    if (!nebula.context || nebula.tintTick === tintTick) return nebula.tinted;

    var paletteShift = nebulaShift(cluster, time);
    var primary = mixColor(cluster.palette[0].primary, cluster.palette[1].primary, paletteShift);
    var secondary = mixColor(cluster.palette[0].secondary, cluster.palette[1].secondary, paletteShift);
    var gradient = nebula.context.createLinearGradient(0, 0, nebula.tinted.width, nebula.tinted.height);

    nebula.context.clearRect(0, 0, nebula.tinted.width, nebula.tinted.height);
    nebula.context.globalCompositeOperation = 'source-over';
    nebula.context.drawImage(nebula.density, 0, 0);
    nebula.context.globalCompositeOperation = 'source-in';
    gradient.addColorStop(0, color(primary, 1));
    gradient.addColorStop(0.56, color(mixColor(primary, secondary, 0.5), 1));
    gradient.addColorStop(1, color(secondary, 1));
    nebula.context.fillStyle = gradient;
    nebula.context.fillRect(0, 0, nebula.tinted.width, nebula.tinted.height);
    nebula.context.globalCompositeOperation = 'source-over';
    nebula.tintTick = tintTick;

    return nebula.tinted;
  }

  function buildField() {
    var random = createRandom(0xc0de71);
    var area = width * height;
    var starCount = Math.max(72, Math.min(190, Math.round(area / 6800)));
    var dustCount = Math.max(110, Math.min(300, Math.round(area / 4300)));
    var starPalette = [
      [211, 229, 255],
      [244, 247, 255],
      [255, 244, 220],
      [255, 213, 169]
    ];

    // Generate the whole composition from the page's seed, including size,
    // orientation and placement. Rebuilding after a resize keeps that identity.
    var layoutRandom = createRandom(cloudSeed ^ 0x6e656275);
    var scale = Math.min(width, height);
    var sceneAngle = layoutRandom() * Math.PI * 2;
    var directionX = Math.cos(sceneAngle);
    var directionY = Math.sin(sceneAngle);
    var edgeDistance = 1 / Math.max(Math.abs(directionX) / (width * 0.5), Math.abs(directionY) / (height * 0.5));
    clusters = [
      {
        palette: [
          {primary: [35, 112, 133], secondary: [55, 91, 142]},
          {primary: [40, 143, 148], secondary: [75, 117, 157]}
        ]
      },
      {
        palette: [
          {primary: [132, 29, 31], secondary: [209, 57, 40]},
          {primary: [181, 42, 31], secondary: [231, 103, 50]}
        ]
      }
    ];

    clusters.forEach(function(cluster, index) {
      var side = index === 0 ? 1 : -1;
      cluster.radius = 0.44 + layoutRandom() * 0.16;
      cluster.rotation = sceneAngle + Math.PI * 0.5 + (layoutRandom() - 0.5) * 1.3;
      cluster.phase = layoutRandom() * Math.PI * 2;
      cluster.squash = 0.6 + layoutRandom() * 0.25;

      var baseRadius = scale * cluster.radius;
      var relativeAngle = cluster.rotation - sceneAngle;
      var majorProjection = 1.8 * Math.cos(relativeAngle);
      var minorProjection = 1.14 * Math.sin(relativeAngle);
      var projectedRadius = baseRadius * Math.sqrt(majorProjection * majorProjection + minorProjection * minorProjection) * 0.7;
      var driftAllowance = Math.min(34, scale * 0.035);
      var distance = Math.max(edgeDistance * (0.6 + layoutRandom() * 0.34), projectedRadius + scale * 0.1 + driftAllowance);
      var lateralOffset = (layoutRandom() - 0.5) * scale * 0.28;

      // Reserve open sky between the visible cloud bodies along their separation
      // axis; their wisps can extend offscreen without forcing corner anchors.
      cluster.x = (width * 0.5 + directionX * distance * side - directionY * lateralOffset) / width;
      cluster.y = (height * 0.5 + directionY * distance * side + directionX * lateralOffset) / height;
    });

    stars = [];
    for (var starIndex = 0; starIndex < starCount; starIndex += 1) {
      stars.push({
        x: random(),
        y: random(),
        size: 0.35 + Math.pow(random(), 3) * 1.55,
        alpha: 0.18 + random() * 0.58,
        phase: random() * Math.PI * 2,
        speed: 0.22 + random() * 0.62,
        drift: 3 + random() * 11,
        velocityX: (0.22 + random() * 0.72) * (random() > 0.5 ? 1 : -1),
        velocityY: (0.08 + random() * 0.26) * (random() > 0.5 ? 1 : -1),
        color: starPalette[Math.floor(random() * starPalette.length)]
      });
    }

    dust = [];
    for (var dustIndex = 0; dustIndex < dustCount; dustIndex += 1) {
      var clusterIndex = Math.floor(random() * clusters.length);
      dust.push({
        cluster: clusterIndex,
        angle: random() * Math.PI * 2,
        radius: Math.pow(random(), 0.72),
        size: 0.3 + Math.pow(random(), 2.4) * 1.8,
        alpha: 0.08 + random() * 0.42,
        phase: random() * Math.PI * 2,
        speed: (0.008 + random() * 0.018) * (random() > 0.5 ? 1 : -1),
        depth: 0.58 + random() * 0.74,
        glow: random() > 0.965
      });
    }

    nebulae = clusters.map(function(cluster, clusterIndex) {
      return buildNebulaTexture(cluster, clusterIndex);
    });
  }

  function clusterPosition(cluster, time) {
    return {
      x: cluster.x * width + Math.sin(time * 0.13 + cluster.phase) * Math.min(34, width * 0.035),
      y: cluster.y * height + Math.cos(time * 0.1 + cluster.phase) * Math.min(28, height * 0.034)
    };
  }

  function drawNebula(time) {
    var scale = Math.min(width, height);

    context.globalCompositeOperation = 'screen';
    context.imageSmoothingEnabled = true;
    clusters.forEach(function(cluster, clusterIndex) {
      var center = clusterPosition(cluster, time);
      var baseRadius = scale * cluster.radius;
      var activeColor = nebulaColor(cluster, time);
      var tintedTexture = tintNebulaTexture(cluster, clusterIndex, time);
      var underglow = context.createRadialGradient(center.x, center.y, 0, center.x, center.y, baseRadius * 1.2);

      underglow.addColorStop(0, color(activeColor, 0.14));
      underglow.addColorStop(0.5, color(activeColor, 0.055));
      underglow.addColorStop(1, color(activeColor, 0));
      context.globalAlpha = 1;
      context.fillStyle = underglow;
      context.beginPath();
      context.arc(center.x, center.y, baseRadius * 1.2, 0, Math.PI * 2);
      context.fill();

      // Two independently moving veils approximate slow gas advection without
      // rebuilding the density field on every frame.
      for (var veil = 0; veil < 2; veil += 1) {
        var direction = veil === 0 ? 1 : -1;
        var motion = time * (veil === 0 ? 0.145 : 0.105) + cluster.phase + veil * 2.4;
        var breathe = 1 + Math.sin(time * (veil === 0 ? 0.13 : 0.098) + cluster.phase) * (veil === 0 ? 0.045 : 0.07);
        var driftX = Math.cos(motion) * baseRadius * (veil === 0 ? 0.12 : 0.18);
        var driftY = Math.sin(motion * 0.83) * baseRadius * (veil === 0 ? 0.08 : 0.12);
        var veilAlpha = veil === 0
          ? 0.75 + Math.sin(time * 0.12 + cluster.phase) * 0.07
          : 0.28 + Math.cos(time * 0.09 + cluster.phase) * 0.04;

        context.save();
        context.translate(center.x + driftX, center.y + driftY);
        context.rotate(cluster.rotation + direction * Math.sin(time * 0.095 + cluster.phase) * (veil === 0 ? 0.065 : 0.1));
        context.scale(veil === 0 ? 1 : -1, 1);
        context.globalAlpha = veilAlpha;
        context.drawImage(
          tintedTexture,
          -baseRadius * 1.8 * breathe,
          -baseRadius * 1.14 / breathe,
          baseRadius * 3.6 * breathe,
          baseRadius * 2.28 / breathe
        );
        context.restore();
      }
    });
  }

  function drawDust(time) {
    var scale = Math.min(width, height);

    context.globalCompositeOperation = 'screen';
    dust.forEach(function(particle) {
      var cluster = clusters[particle.cluster];
      var center = clusterPosition(cluster, time);
      var dustColor = nebulaColor(cluster, time);
      var angle = particle.angle + time * particle.speed;
      var radius = scale * cluster.radius * particle.radius * particle.depth;
      var x = center.x + Math.cos(angle) * radius * 1.3;
      var y = center.y + Math.sin(angle) * radius * cluster.squash;
      var shimmer = 0.68 + Math.sin(time * 0.55 + particle.phase) * 0.32;

      if (x < -12 || x > width + 12 || y < -12 || y > height + 12) return;

      context.globalAlpha = particle.alpha * shimmer;
      context.fillStyle = color(dustColor, 1);
      if (particle.glow) {
        context.shadowBlur = 9;
        context.shadowColor = color(dustColor, 0.75);
      }
      context.beginPath();
      context.arc(x, y, particle.size, 0, Math.PI * 2);
      context.fill();
      context.shadowBlur = 0;
    });
  }

  function drawStars(time) {
    context.globalCompositeOperation = 'screen';
    stars.forEach(function(star) {
      var margin = 18;
      var travelWidth = width + margin * 2;
      var travelHeight = height + margin * 2;
      var starX = star.x * width + time * star.velocityX + Math.sin(time * 0.09 + star.phase) * star.drift + margin;
      var starY = star.y * height + time * star.velocityY + Math.cos(time * 0.072 + star.phase) * star.drift * 0.65 + margin;
      var x = ((starX % travelWidth) + travelWidth) % travelWidth - margin;
      var y = ((starY % travelHeight) + travelHeight) % travelHeight - margin;
      var twinkle = 0.58 + Math.sin(time * star.speed + star.phase) * 0.42;

      context.globalAlpha = star.alpha * twinkle;
      context.fillStyle = color(star.color, 1);
      context.beginPath();
      context.arc(x, y, star.size, 0, Math.PI * 2);
      context.fill();
    });
  }

  function drawMeteor(time, offset, duration, stream) {
    var shiftedTime = time + offset;
    var pass = Math.floor(shiftedTime / duration);
    var activeTime = shiftedTime - pass * duration;
    // Each pass gets a stable seeded trajectory. Randomizing by pass instead of
    // by frame prevents the meteor from jumping while it crosses the viewport.
    var startYRatio = 0.06 + noiseHash(pass, stream, 7307) * 0.58;
    var verticalTravel = height * (0.09 + noiseHash(pass, stream, 9011) * 0.17);
    var travelsRight = noiseHash(pass, stream, 11149) > 0.38;
    var activeDuration = 1.9 + noiseHash(pass, stream, 12647) * 1.7;

    if (activeTime > activeDuration || reducedMotion) return;

    var progress = activeTime / activeDuration;
    var direction = travelsRight ? 1 : -1;
    var x = width * (travelsRight ? -0.12 + progress * 1.24 : 1.12 - progress * 1.24);
    var y = height * startYRatio + progress * verticalTravel;
    var trail = Math.min(175, width * (0.09 + noiseHash(pass, stream, 14533) * 0.08));
    var trailSlope = verticalTravel / (width * 1.24);
    var tailX = x - direction * trail;
    var tailY = y - trail * trailSlope;
    var opacity = Math.sin(progress * Math.PI) * (0.28 + noiseHash(pass, stream, 16633) * 0.16);
    var gradient = context.createLinearGradient(tailX, tailY, x, y);

    gradient.addColorStop(0, 'rgba(45, 212, 191, 0)');
    gradient.addColorStop(1, 'rgba(255, 248, 231, ' + opacity + ')');
    context.globalCompositeOperation = 'screen';
    context.globalAlpha = 1;
    context.strokeStyle = gradient;
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(tailX, tailY);
    context.lineTo(x, y);
    context.stroke();
  }

  function draw(time) {
    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.clearRect(0, 0, width, height);
    context.globalAlpha = 1;
    context.shadowBlur = 0;
    drawNebula(time);
    drawDust(time);
    drawStars(time);
    drawMeteor(time, 4.5, 23, 1);
    drawMeteor(time, 15, 31, 2);
    context.globalAlpha = 1;
    context.globalCompositeOperation = 'source-over';
  }

  function setSize() {
    width = Math.max(1, document.documentElement.clientWidth || window.innerWidth);
    height = Math.max(1, document.documentElement.clientHeight || window.innerHeight);
    pixelRatio = Math.min(window.devicePixelRatio || 1, 1.5);
    canvas.width = Math.round(width * pixelRatio);
    canvas.height = Math.round(height * pixelRatio);
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    buildField();
    draw(reducedMotion ? 0 : performance.now() / 1000);
  }

  function animate(timestamp) {
    frameId = 0;
    if (timestamp - lastFrameTime >= frameInterval) {
      lastFrameTime = timestamp;
      draw(timestamp / 1000);
    }
    startAnimation();
  }

  function startAnimation() {
    if (frameId || reducedMotion || document.hidden) return;
    frameId = window.requestAnimationFrame(animate);
  }

  function stopAnimation() {
    if (!frameId) return;
    window.cancelAnimationFrame(frameId);
    frameId = 0;
  }

  function requestResize() {
    if (resizeId) window.clearTimeout(resizeId);
    resizeId = window.setTimeout(function() {
      resizeId = 0;
      setSize();
    }, 120);
  }

  function updateMotionPreference(event) {
    reducedMotion = event.matches;
    stopAnimation();
    draw(reducedMotion ? 0 : performance.now() / 1000);
    startAnimation();
  }

  window.addEventListener('resize', requestResize, {passive: true});
  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      stopAnimation();
    } else {
      startAnimation();
    }
  });

  if (motionPreference.addEventListener) {
    motionPreference.addEventListener('change', updateMotionPreference);
  }

  setSize();
  startAnimation();
})();

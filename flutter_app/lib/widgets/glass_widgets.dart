import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';
import '../utils/app_palette.dart';
import '../utils/perf_config.dart';

// ═══════════════════════════════════════════════════════════════════════════════
// 1. GLASS ORB BACKGROUND (Ambient Optical Refraction Canvas)
// ═══════════════════════════════════════════════════════════════════════════════
/// ផ្ទៃខាងក្រោយបែប Glassmorphic Canvas ដែលមាន Ambient Light Orbs
/// សម្រាប់ឱ្យកញ្ចក់ព្រាល (BackdropFilter) ឆ្លុះពន្លឺពណ៌មាស ពណ៌ខៀវ និងស្វាយយ៉ាងស្រស់ស្អាត។
class GlassOrbBackground extends StatefulWidget {
  final Widget child;
  final bool animate;
  final Color? baseColor;
  final Color? primaryOrbColor;
  final Color? secondaryOrbColor;
  final Color? accentOrbColor;
  final double orbOpacity;

  const GlassOrbBackground({
    super.key,
    required this.child,
    this.animate = true,
    this.baseColor,
    this.primaryOrbColor,
    this.secondaryOrbColor,
    this.accentOrbColor,
    this.orbOpacity = 0.16,
  });

  @override
  State<GlassOrbBackground> createState() => _GlassOrbBackgroundState();
}

class _GlassOrbBackgroundState extends State<GlassOrbBackground>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 12),
    );
    if (widget.animate) {
      _controller.repeat(reverse: true);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.palette;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg = widget.baseColor ?? palette.background;
    final goldColor = widget.primaryOrbColor ?? AppTheme.primary;
    final blueColor = widget.secondaryOrbColor ?? const Color(0xFF2563EB);
    final purpleColor = widget.accentOrbColor ?? const Color(0xFF8B5CF6);

    final bool isLight = !isDark;
    final List<Color> bgColors = isLight
        ? [
            palette.background,
            palette.cardSurface,
            const Color(0xFFEFF6FF),
          ]
        : [
            bg,
            Color.lerp(bg, const Color(0xFF0F172A), 0.7) ?? bg,
            Color.lerp(bg, const Color(0xFF020617), 0.9) ?? bg,
          ];

    final double topGoldAlpha = isLight ? 0.14 : widget.orbOpacity;
    final double midSkyAlpha = isLight ? 0.08 : widget.orbOpacity * 0.9;
    final double warmAccentAlpha = isLight ? 0.09 : widget.orbOpacity * 0.85;
    final double bottomAccentAlpha = isLight ? 0.06 : widget.orbOpacity * 0.75;

    final shouldAnimate = widget.animate && !PerfConfig.isLowEndDevice;

    return Scaffold(
      backgroundColor: bg,
      body: Stack(
        fit: StackFit.expand,
        children: [
          // Base Deep Mesh Background
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: bgColors,
              ),
            ),
          ),

          // Dynamic Ambient Glowing Orbs (Static on low-end devices to eliminate jank)
          if (shouldAnimate)
            AnimatedBuilder(
              animation: _controller,
              builder: (context, _) {
                final progress = _controller.value;
                return Stack(
                  children: [
                    // Top-Right Gold Glow Orb (Pulsing)
                    Positioned(
                      top: -60 + (progress * 30),
                      right: -50 - (progress * 25),
                      child: _buildGlowOrb(
                        color: goldColor,
                        size: 280 + (progress * 40),
                        opacity: topGoldAlpha,
                      ),
                    ),
                    // Top-Left Soft Sky Glow Orb
                    Positioned(
                      top: 140 - (progress * 35),
                      left: -80 + (progress * 25),
                      child: _buildGlowOrb(
                        color: blueColor,
                        size: 250,
                        opacity: midSkyAlpha,
                      ),
                    ),
                    // Center-Right Warm Brand Accent Glow Orb
                    Positioned(
                      top: 420 + (progress * 40),
                      right: -70 + (progress * 20),
                      child: _buildGlowOrb(
                        color: isLight ? goldColor : purpleColor,
                        size: 230,
                        opacity: warmAccentAlpha,
                      ),
                    ),
                    // Bottom-Left Ambient Glow Orb
                    Positioned(
                      bottom: -50 - (progress * 20),
                      left: -40 + (progress * 30),
                      child: _buildGlowOrb(
                        color: isLight ? const Color(0xFF38BDF8) : const Color(0xFF10B981),
                        size: 250,
                        opacity: bottomAccentAlpha,
                      ),
                    ),
                  ],
                );
              },
            )
          else
            Stack(
              children: [
                Positioned(
                  top: -50,
                  right: -40,
                  child: _buildGlowOrb(
                    color: goldColor,
                    size: 280,
                    opacity: topGoldAlpha,
                  ),
                ),
                Positioned(
                  top: 160,
                  left: -70,
                  child: _buildGlowOrb(
                    color: blueColor,
                    size: 250,
                    opacity: midSkyAlpha,
                  ),
                ),
                Positioned(
                  bottom: 80,
                  right: -50,
                  child: _buildGlowOrb(
                    color: isLight ? goldColor : purpleColor,
                    size: 230,
                    opacity: warmAccentAlpha,
                  ),
                ),
              ],
            ),

          // Main Foreground Content
          widget.child,
        ],
      ),
    );
  }

  Widget _buildGlowOrb({
    required Color color,
    required double size,
    required double opacity,
  }) {
    return IgnorePointer(
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: RadialGradient(
            colors: [
              color.withValues(alpha: opacity),
              color.withValues(alpha: opacity * 0.5),
              color.withValues(alpha: 0.0),
            ],
            stops: const [0.0, 0.45, 1.0],
          ),
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. GLASS CARD (Frosted Glass Container with Specular Edge Reflection)
// ═══════════════════════════════════════════════════════════════════════════════
/// កាតកញ្ចក់ព្រាលទំនើប ដែលមាន Gradient Border, Specular Top Highlight និង Blur ស៊ីវិល័យ
class GlassCard extends StatelessWidget {
  final Widget child;
  final double blur;
  final double borderRadius;
  final Color? tintColor;
  final double opacity;
  final Color? borderColor;
  final Gradient? borderGradient;
  final double borderWidth;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final VoidCallback? onTap;
  final Color? glowColor;
  final double glowBlur;
  final bool hasTopShine;
  final BoxConstraints? constraints;

  const GlassCard({
    super.key,
    required this.child,
    this.blur = 20.0,
    this.borderRadius = 22.0,
    this.tintColor,
    this.opacity = 0.72,
    this.borderColor,
    this.borderGradient,
    this.borderWidth = 1.2,
    this.padding,
    this.margin,
    this.onTap,
    this.glowColor,
    this.glowBlur = 18.0,
    this.hasTopShine = false,
    this.constraints,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.palette;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final baseTint = tintColor ?? palette.card;
    final double effOpacity = isDark
        ? (opacity < 0.3 ? opacity : 0.22)
        : (opacity > 0.85 ? 0.95 : (opacity < 0.3 ? 0.88 : opacity));

    // Clean, natural border: uses uniform borderColor if provided, or high-contrast palette border
    final effectiveBorderGrad = borderGradient ??
        (borderColor != null
            ? LinearGradient(
                colors: [borderColor!, borderColor!],
              )
            : LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: isDark
                    ? [
                        Colors.white.withValues(alpha: 0.18),
                        Colors.white.withValues(alpha: 0.10),
                        Colors.white.withValues(alpha: 0.05),
                        Colors.white.withValues(alpha: 0.12),
                      ]
                    : [
                        palette.border.withValues(alpha: 0.90),
                        palette.border.withValues(alpha: 0.60),
                        palette.border.withValues(alpha: 0.40),
                        palette.border.withValues(alpha: 0.80),
                      ],
                stops: const [0.0, 0.4, 0.75, 1.0],
              ));

    // Inner frosted gradient
    final innerSurfaceGrad = LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: isDark
          ? [
              baseTint.withValues(alpha: (effOpacity * 1.05).clamp(0.0, 0.96)),
              baseTint.withValues(alpha: effOpacity.clamp(0.0, 0.92)),
              baseTint.withValues(alpha: (effOpacity * 0.90).clamp(0.0, 0.88)),
            ]
          : [
              baseTint.withValues(alpha: 0.98),
              baseTint.withValues(alpha: 0.94),
              baseTint.withValues(alpha: 0.92),
            ],
      stops: const [0.0, 0.5, 1.0],
    );

    Widget cardContent = Container(
      constraints: constraints,
      padding: padding ?? const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: innerSurfaceGrad,
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: child,
    );

    final bool enableBlur = PerfConfig.shouldEnableBlur(context);

    Widget frostedCore = CustomPaint(
      painter: _GlassBorderPainter(
        borderRadius: borderRadius,
        borderWidth: borderWidth,
        gradient: effectiveBorderGrad,
      ),
      child: cardContent,
    );

    Widget surface = enableBlur
        ? BackdropFilter(
            filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
            child: frostedCore,
          )
        : frostedCore;

    Widget cardBody = Container(
      margin: margin,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(borderRadius),
        boxShadow: [
          // Ambient depth shadow
          BoxShadow(
            color: isDark
                ? const Color(0xFF0F172A).withValues(alpha: 0.25)
                : const Color(0xFF64748B).withValues(alpha: 0.08),
            blurRadius: isDark ? 16 : 10,
            offset: const Offset(0, 3),
          ),
          // Glow shadow if configured
          if (glowColor != null)
            BoxShadow(
              color: glowColor!.withValues(alpha: 0.22),
              blurRadius: glowBlur,
              spreadRadius: -1,
            ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(borderRadius),
        child: surface,
      ),
    );

    if (onTap != null) {
      return GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: () {
          HapticFeedback.lightImpact();
          onTap!();
        },
        child: cardBody,
      );
    }

    return cardBody;
  }
}

/// Custom painter សម្រាប់គូរ Gradient Border ដ៏ម៉ដ្ត និងថ្លាលើកញ្ចក់
class _GlassBorderPainter extends CustomPainter {
  final double borderRadius;
  final double borderWidth;
  final Gradient gradient;

  _GlassBorderPainter({
    required this.borderRadius,
    required this.borderWidth,
    required this.gradient,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (borderWidth <= 0) return;

    final rect = Offset.zero & size;
    final rrect = RRect.fromRectAndRadius(
      rect.deflate(borderWidth / 2),
      Radius.circular(borderRadius),
    );

    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = borderWidth
      ..shader = gradient.createShader(rect);

    canvas.drawRRect(rrect, paint);
  }

  @override
  bool shouldRepaint(covariant _GlassBorderPainter oldDelegate) {
    return oldDelegate.borderRadius != borderRadius ||
        oldDelegate.borderWidth != borderWidth ||
        oldDelegate.gradient != gradient;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. GLASS BUTTON (Interactive Frosted Glass Action Button)
// ═══════════════════════════════════════════════════════════════════════════════
/// ប៊ូតុងកញ្ចក់ព្រាលប្រណិត មាន Micro-press scale និង Glowing border
class GlassButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final Widget? child;
  final String? label;
  final IconData? icon;
  final Color? color;
  final Color? textColor;
  final double borderRadius;
  final double height;
  final EdgeInsetsGeometry? padding;
  final bool isLoading;
  final bool glow;

  const GlassButton({
    super.key,
    required this.onPressed,
    this.child,
    this.label,
    this.icon,
    this.color,
    this.textColor,
    this.borderRadius = 16.0,
    this.height = 48.0,
    this.padding,
    this.isLoading = false,
    this.glow = true,
  });

  @override
  State<GlassButton> createState() => _GlassButtonState();
}

class _GlassButtonState extends State<GlassButton> {
  bool _isPressed = false;

  @override
  Widget build(BuildContext context) {
    final palette = context.palette;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final themeColor = widget.color ?? AppTheme.primary;
    final textCol = widget.textColor ??
        (widget.color != null
            ? (themeColor.computeLuminance() > 0.5 ? const Color(0xFF0F172A) : Colors.white)
            : (isDark ? Colors.white : palette.textPrimary));
    final enableBlur = PerfConfig.shouldEnableBlur(context);

    Widget innerBtn = Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: isDark
              ? [
                  themeColor.withValues(alpha: 0.35),
                  themeColor.withValues(alpha: 0.18),
                ]
              : [
                  themeColor.withValues(alpha: 0.15),
                  themeColor.withValues(alpha: 0.08),
                ],
        ),
        borderRadius: BorderRadius.circular(widget.borderRadius),
        border: Border.all(
          color: themeColor.withValues(alpha: isDark ? 0.45 : 0.35),
          width: 1.2,
        ),
      ),
      child: Center(
        child: widget.isLoading
            ? SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(
                  strokeWidth: 2.2,
                  valueColor: AlwaysStoppedAnimation<Color>(textCol),
                ),
              )
            : widget.child ??
                Row(
                  mainAxisSize: MainAxisSize.min,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    if (widget.icon != null) ...[
                      Icon(widget.icon, color: textCol, size: 18),
                      const SizedBox(width: 8),
                    ],
                    if (widget.label != null)
                      Text(
                        widget.label!,
                        style: GoogleFonts.kantumruyPro(
                          color: textCol,
                          fontSize: 14,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                  ],
                ),
      ),
    );

    return AnimatedScale(
      scale: _isPressed ? 0.96 : 1.0,
      duration: const Duration(milliseconds: 120),
      curve: Curves.easeOutCubic,
      child: GestureDetector(
        onTapDown: (_) {
          if (widget.onPressed != null && !widget.isLoading) {
            setState(() => _isPressed = true);
          }
        },
        onTapUp: (_) {
          if (_isPressed) {
            setState(() => _isPressed = false);
          }
        },
        onTapCancel: () {
          if (_isPressed) {
            setState(() => _isPressed = false);
          }
        },
        onTap: () {
          if (widget.onPressed != null && !widget.isLoading) {
            HapticFeedback.lightImpact();
            widget.onPressed!();
          }
        },
        child: Container(
          height: widget.height,
          padding: widget.padding ?? const EdgeInsets.symmetric(horizontal: 18),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(widget.borderRadius),
            boxShadow: widget.glow
                ? [
                    BoxShadow(
                      color: themeColor.withValues(alpha: isDark ? 0.28 : 0.15),
                      blurRadius: 16,
                      offset: const Offset(0, 4),
                    ),
                  ]
                : null,
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(widget.borderRadius),
            child: enableBlur
                ? BackdropFilter(
                    filter: ui.ImageFilter.blur(sigmaX: 16, sigmaY: 16),
                    child: innerBtn,
                  )
                : innerBtn,
          ),
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GLASS CHIP / BADGE (Frosted Pill for Status, Weather, Streaks)
// ═══════════════════════════════════════════════════════════════════════════════
/// ស្លាកកញ្ចក់ព្រាលតូចល្មមសម្រាប់បង្ហាញស្ថានភាព អាកាសធាតុ ឬ Streak
class GlassChip extends StatelessWidget {
  final Widget? icon;
  final String label;
  final Color? color;
  final Color? textColor;
  final VoidCallback? onTap;
  final EdgeInsetsGeometry padding;
  final double borderRadius;

  const GlassChip({
    super.key,
    this.icon,
    required this.label,
    this.color,
    this.textColor,
    this.onTap,
    this.padding = const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
    this.borderRadius = 20.0,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.palette;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final baseColor = color ?? (isDark ? Colors.white : palette.card);
    final textCol = textColor ?? (color ?? palette.textPrimary);
    final enableBlur = PerfConfig.shouldEnableBlur(context);

    Widget chipCore = Container(
      padding: padding,
      decoration: BoxDecoration(
        color: isDark
            ? baseColor.withValues(alpha: 0.12)
            : (color != null ? color!.withValues(alpha: 0.12) : palette.cardSurface),
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: isDark
              ? baseColor.withValues(alpha: 0.28)
              : (color != null ? color!.withValues(alpha: 0.35) : palette.border),
          width: 1.0,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[
            icon!,
            const SizedBox(width: 6),
          ],
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: textCol,
              fontSize: 12,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );

    Widget chip = ClipRRect(
      borderRadius: BorderRadius.circular(borderRadius),
      child: enableBlur
          ? BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: 14, sigmaY: 14),
              child: chipCore,
            )
          : chipCore,
    );

    if (onTap != null) {
      return GestureDetector(
        onTap: () {
          HapticFeedback.lightImpact();
          onTap!();
        },
        child: chip,
      );
    }
    return chip;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. GLASS CONTAINER (Low-Level Frosted Wrapper)
// ═══════════════════════════════════════════════════════════════════════════════
class GlassContainer extends StatelessWidget {
  final Widget child;
  final double blur;
  final double borderRadius;
  final Color? color;
  final Color? borderColor;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final double? width;
  final double? height;

  const GlassContainer({
    super.key,
    required this.child,
    this.blur = 18.0,
    this.borderRadius = 18.0,
    this.color,
    this.borderColor,
    this.padding,
    this.margin,
    this.width,
    this.height,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.palette;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final baseColor = color ?? (isDark ? Colors.white : palette.card);
    final enableBlur = PerfConfig.shouldEnableBlur(context);

    Widget innerContainer = Container(
      padding: padding,
      decoration: BoxDecoration(
        color: isDark
            ? baseColor.withValues(alpha: 0.08)
            : palette.card.withValues(alpha: 0.90),
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: borderColor ??
              (isDark
                  ? baseColor.withValues(alpha: 0.18)
                  : palette.border),
          width: 1.0,
        ),
      ),
      child: child,
    );

    return Container(
      width: width,
      height: height,
      margin: margin,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(borderRadius),
        child: enableBlur
            ? BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
                child: innerContainer,
              )
            : innerContainer,
      ),
    );
  }
}

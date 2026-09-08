import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';

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
    final bg = widget.baseColor ?? AppTheme.bgDark;
    final goldColor = widget.primaryOrbColor ?? AppTheme.primary;
    final blueColor = widget.secondaryOrbColor ?? const Color(0xFF2563EB);
    final purpleColor = widget.accentOrbColor ?? const Color(0xFF8B5CF6);

    final bool isLight = bg.computeLuminance() > 0.4;
    final List<Color> bgColors = isLight
        ? [
            bg,
            Color.lerp(bg, Colors.white, 0.6) ?? bg,
            Color.lerp(bg, const Color(0xFFEDE9FE), 0.2) ?? bg,
          ]
        : [
            bg,
            Color.lerp(bg, const Color(0xFF0F172A), 0.7) ?? bg,
            Color.lerp(bg, const Color(0xFF020617), 0.9) ?? bg,
          ];

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

          // Dynamic Ambient Glowing Orbs
          if (widget.animate)
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
                        size: 260 + (progress * 40),
                        opacity: widget.orbOpacity,
                      ),
                    ),
                    // Top-Left Blue Glow Orb
                    Positioned(
                      top: 140 - (progress * 35),
                      left: -80 + (progress * 25),
                      child: _buildGlowOrb(
                        color: blueColor,
                        size: 240,
                        opacity: widget.orbOpacity * 0.9,
                      ),
                    ),
                    // Center-Right Purple Glow Orb
                    Positioned(
                      top: 420 + (progress * 40),
                      right: -70 + (progress * 20),
                      child: _buildGlowOrb(
                        color: purpleColor,
                        size: 220,
                        opacity: widget.orbOpacity * 0.85,
                      ),
                    ),
                    // Bottom-Left Emerald/Cyan Accent Orb
                    Positioned(
                      bottom: -50 - (progress * 20),
                      left: -40 + (progress * 30),
                      child: _buildGlowOrb(
                        color: const Color(0xFF10B981),
                        size: 250,
                        opacity: widget.orbOpacity * 0.75,
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
                    size: 270,
                    opacity: widget.orbOpacity,
                  ),
                ),
                Positioned(
                  top: 160,
                  left: -70,
                  child: _buildGlowOrb(
                    color: blueColor,
                    size: 240,
                    opacity: widget.orbOpacity * 0.85,
                  ),
                ),
                Positioned(
                  bottom: 80,
                  right: -50,
                  child: _buildGlowOrb(
                    color: purpleColor,
                    size: 220,
                    opacity: widget.orbOpacity * 0.8,
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
    this.opacity = 0.09,
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
    final baseTint = tintColor ?? Colors.white;

    // Clean, natural border: uses uniform borderColor if provided, or smooth subtle gradient
    final effectiveBorderGrad = borderGradient ??
        (borderColor != null
            ? LinearGradient(
                colors: [borderColor!, borderColor!],
              )
            : LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  baseTint.withValues(alpha: 0.20),
                  baseTint.withValues(alpha: 0.12),
                  baseTint.withValues(alpha: 0.08),
                  baseTint.withValues(alpha: 0.14),
                ],
                stops: const [0.0, 0.4, 0.75, 1.0],
              ));

    // Inner frosted gradient
    final innerSurfaceGrad = LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: [
        baseTint.withValues(alpha: opacity * 1.3),
        baseTint.withValues(alpha: opacity),
        baseTint.withValues(alpha: opacity * 0.7),
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

    Widget cardBody = Container(
      margin: margin,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(borderRadius),
        boxShadow: [
          // Ambient depth shadow
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.10),
            blurRadius: 16,
            offset: const Offset(0, 6),
          ),
          // Glow shadow if configured
          if (glowColor != null)
            BoxShadow(
              color: glowColor!.withValues(alpha: 0.26),
              blurRadius: glowBlur,
              spreadRadius: -1,
            ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(borderRadius),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
          child: CustomPaint(
            painter: _GlassBorderPainter(
              borderRadius: borderRadius,
              borderWidth: borderWidth,
              gradient: effectiveBorderGrad,
            ),
            child: cardContent,
          ),
        ),
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
    final themeColor = widget.color ?? AppTheme.primary;
    final textCol = widget.textColor ?? Colors.white;

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
                      color: themeColor.withValues(alpha: 0.28),
                      blurRadius: 16,
                      offset: const Offset(0, 4),
                    ),
                  ]
                : null,
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(widget.borderRadius),
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: 16, sigmaY: 16),
              child: Container(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [
                      themeColor.withValues(alpha: 0.32),
                      themeColor.withValues(alpha: 0.18),
                    ],
                  ),
                  borderRadius: BorderRadius.circular(widget.borderRadius),
                  border: Border.all(
                    color: themeColor.withValues(alpha: 0.45),
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
              ),
            ),
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
    final baseColor = color ?? Colors.white;
    final textCol = textColor ?? (color ?? AppTheme.textPrimary);

    Widget chip = ClipRRect(
      borderRadius: BorderRadius.circular(borderRadius),
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: 14, sigmaY: 14),
        child: Container(
          padding: padding,
          decoration: BoxDecoration(
            color: baseColor.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(borderRadius),
            border: Border.all(
              color: baseColor.withValues(alpha: 0.28),
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
        ),
      ),
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
    final baseColor = color ?? Colors.white;
    return Container(
      width: width,
      height: height,
      margin: margin,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(borderRadius),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
          child: Container(
            padding: padding,
            decoration: BoxDecoration(
              color: baseColor.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(borderRadius),
              border: Border.all(
                color: borderColor ?? baseColor.withValues(alpha: 0.18),
                width: 1.0,
              ),
            ),
            child: child,
          ),
        ),
      ),
    );
  }
}

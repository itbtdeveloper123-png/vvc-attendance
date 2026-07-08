import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../services/app_update_service.dart';
import '../utils/app_theme.dart';

Future<void> showAppUpdateDialog({
  required BuildContext context,
  required String version,
  required String message,
  required String apkUrl,
  required bool forceUpdate,
}) {
  double downloadProgress = 0;
  bool isDownloading = false;
  String statusText = 'កំពុងរៀបចំទាញយក...';
  final displayMessage = message.trim().isNotEmpty
      ? message.trim()
      : 'កម្មវិធីមានជំនាន់ថ្មី។ សូមធ្វើការអាប់ដេត។';

  return showDialog<void>(
    context: context,
    barrierDismissible: !forceUpdate,
    builder: (ctx) => StatefulBuilder(
      builder: (dialogContext, setDialogState) => PopScope(
        canPop: !forceUpdate && !isDownloading,
        child: AlertDialog(
          backgroundColor: AppTheme.bgCard,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24),
          ),
          icon: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.primary.withValues(alpha: 0.1),
              shape: BoxShape.circle,
            ),
            child: Icon(
              isDownloading
                  ? Icons.downloading_rounded
                  : Icons.system_update_rounded,
              color: AppTheme.primary,
              size: 40,
            ),
          ),
          title: Text(
            isDownloading
                ? 'កំពុងទាញយកជំនាន់ថ្មី'
                : 'កម្មវិធីមានជំនាន់ថ្មី V$version',
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
            textAlign: TextAlign.center,
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (!isDownloading)
                Text(
                  displayMessage,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textSecondary,
                    fontSize: 14,
                  ),
                  textAlign: TextAlign.center,
                ),
              if (isDownloading) ...[
                const SizedBox(height: 10),
                ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: LinearProgressIndicator(
                    value: downloadProgress,
                    minHeight: 10,
                    backgroundColor: Colors.white10,
                    valueColor: AlwaysStoppedAnimation<Color>(AppTheme.primary),
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  '${(downloadProgress * 100).toStringAsFixed(0)}%',
                  style: GoogleFonts.inter(
                    color: AppTheme.primary,
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  statusText,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textMuted,
                    fontSize: 12,
                  ),
                  textAlign: TextAlign.center,
                ),
              ],
            ],
          ),
          actionsPadding: const EdgeInsets.fromLTRB(16, 0, 16, 20),
          actions: [
            if (!isDownloading)
              Column(
                children: [
                  SizedBox(
                    width: double.infinity,
                    height: 48,
                    child: ElevatedButton(
                      onPressed: () async {
                        setDialogState(() {
                          isDownloading = true;
                          downloadProgress = 0;
                          statusText = 'កំពុងរៀបចំទាញយក...';
                        });

                        final errorMessage =
                            await AppUpdateService.downloadAndInstallApk(
                              apkUrl,
                              onProgress: (progress, status) {
                                if (!dialogContext.mounted) return;
                                setDialogState(() {
                                  downloadProgress = progress;
                                  statusText = status;
                                });
                              },
                            );

                        if (!dialogContext.mounted) return;

                        if (errorMessage == null) {
                          Navigator.of(dialogContext).pop();
                          return;
                        }

                        setDialogState(() {
                          isDownloading = false;
                          downloadProgress = 0;
                          statusText = errorMessage;
                        });

                        if (!context.mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text(
                              errorMessage,
                              style: GoogleFonts.kantumruyPro(),
                            ),
                          ),
                        );
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        foregroundColor: Colors.white,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12),
                        ),
                      ),
                      child: Text(
                        'អាប់ដេតឥឡូវនេះ',
                        style: GoogleFonts.kantumruyPro(
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ),
                  if (!forceUpdate) ...[
                    const SizedBox(height: 8),
                    TextButton(
                      onPressed: () => Navigator.pop(ctx),
                      child: Text(
                        'ទុកពេលក្រោយ',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                        ),
                      ),
                    ),
                  ],
                ],
              ),
          ],
        ),
      ),
    ),
  );
}

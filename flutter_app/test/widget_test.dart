import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';

import 'package:vvc_hrm/core/theme/theme_provider.dart';
import 'package:vvc_hrm/main.dart';
import 'package:vvc_hrm/providers/user_provider.dart';

void main() {
  testWidgets('VVC HRM app builds', (WidgetTester tester) async {
    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider(create: (_) => UserProvider()),
          ChangeNotifierProvider(create: (_) => SeasonalThemeProvider()),
        ],
        child: const VvcHrmApp(),
      ),
    );

    expect(find.byType(MaterialApp), findsOneWidget);

    await tester.pump();
    await tester.pump(const Duration(seconds: 2));
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump();
  });
}

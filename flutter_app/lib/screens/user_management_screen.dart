import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class UserManagementScreen extends StatefulWidget {
  const UserManagementScreen({super.key});

  @override
  State<UserManagementScreen> createState() => _UserManagementScreenState();
}

class _UserManagementScreenState extends State<UserManagementScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _users = [];
  List<dynamic> _filtered = [];
  bool _isLoading = true;
  final TextEditingController _searchController = TextEditingController();
  Timer? _pollingTimer;

  bool _isListView = false;
  String _selectedDept = 'All';
  String _selectedRole = 'All';
  String _selectedStatus = 'All';

  String _groupLabel(Map<String, dynamic> u) {
    final branch = (u['branch'] ?? '').toString().trim();
    if (branch.isNotEmpty) return branch;
    final dept = (u['department'] ?? '').toString().trim();
    if (dept.isNotEmpty) return dept;
    return 'Other';
  }

  @override
  void initState() {
    super.initState();
    _loadUsers();
    _searchController.addListener(_onSearch);

    _pollingTimer = Timer.periodic(const Duration(seconds: 60), (timer) {
      if (mounted) {
        _loadUsersSilently();
      }
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadUsers() async {
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchUsers();
      if (!mounted) return;
      if (res['success'] == true) {
        setState(() {
          _users = res['data'] ?? [];
          _filtered = List.from(_users);
          _isLoading = false;
        });
      } else {
        setState(() => _isLoading = false);
        _showError(res['message'] ?? 'Error fetching users');
      }
    } catch (e) {
      if (!mounted) return;
      setState(() => _isLoading = false);
      _showError('Connection error: $e');
    }
  }

  Future<void> _loadUsersSilently() async {
    try {
      final res = await _api.fetchUsers();
      if (!mounted) return;
      if (res['success'] == true) {
        setState(() {
          _users = res['data'] ?? [];
          _onSearch();
        });
      }
    } catch (_) {}
  }

  void _onSearch() {
    final query = _searchController.text.toLowerCase();
    setState(() {
      _filtered = _users.where((u) {
        final mapU = Map<String, dynamic>.from(u as Map);
        final name = (mapU['name'] ?? '').toString().toLowerCase();
        final eid = (mapU['employee_id'] ?? '').toString().toLowerCase();

        final dept = _groupLabel(mapU).trim();
        final roleStr =
            (mapU['system_role_label']?.toString() ??
                    mapU['system_role']?.toString() ??
                    '')
                .trim();
        final stat = (mapU['status'] ?? 'Active').toString().trim();

        bool matchQuery = name.contains(query) || eid.contains(query);
        bool matchDept = _selectedDept == 'All' || dept == _selectedDept;
        bool matchRole = _selectedRole == 'All' || roleStr == _selectedRole;
        bool matchStatus = _selectedStatus == 'All' || stat == _selectedStatus;

        return matchQuery && matchDept && matchRole && matchStatus;
      }).toList();
    });
  }

  Future<void> _exportToCSV() async {
    try {
      final buffer = StringBuffer();
      buffer.writeln(
        'ID,Name,Latin Name,Gender,Department,Position,Branch,Role,Status,Joined At,Base Salary',
      );
      for (final u in _filtered) {
        buffer.writeln(
          '${u['employee_id']},${u['name']},${u['latin_name'] ?? ''},${u['gender'] ?? ''},${u['department'] ?? ''},${u['position'] ?? ''},${u['branch'] ?? ''},${u['system_role'] ?? ''},${u['status'] ?? 'Active'},${u['joined_at'] ?? ''},${u['base_salary'] ?? ''}',
        );
      }
      final dir = await getApplicationDocumentsDirectory();
      final path =
          '${dir.path}/user_export_${DateTime.now().millisecondsSinceEpoch}.csv';
      await File(path).writeAsString(buffer.toString());
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'បានរក្សាទុក (Exported): $path',
              style: GoogleFonts.kantumruyPro(color: Colors.white),
            ),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      if (mounted) _showError('Export failed: $e');
    }
  }

  void _showError(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: Colors.redAccent),
    );
  }

  @override
  Widget build(BuildContext context) {
    return DynamicAppBarWrapper(
      title: "គ្រប់គ្រងបុគ្គលិក",
      actions: [
        IconButton(
          icon: const Icon(Icons.download_rounded),
          onPressed: _exportToCSV,
          tooltip: 'Export CSV',
        ),
        IconButton(
          icon: const Icon(Icons.person_add_rounded),
          onPressed: () => _editUser(null),
        ),
        IconButton(
          icon: const Icon(Icons.refresh_rounded),
          onPressed: _loadUsers,
        ),
      ],
      body: AppBackgroundShell(
        child: Column(
          children: [
            SizedBox(height: MediaQuery.of(context).padding.top + 70),
            Padding(
              padding: const EdgeInsets.symmetric(
                horizontal: 16.0,
                vertical: 8.0,
              ),
              child: Row(
                children: [
                  Expanded(
                    child: AppSearchField(
                      controller: _searchController,
                      hintText: "ស្វែងរកឈ្មោះ ឬ ID...",
                      borderRadius: 15,
                      backgroundColor: AppTheme.textPrimary.withValues(
                        alpha: 0.05,
                      ),
                      borderColor: Colors.transparent,
                      iconColor: AppTheme.textPrimary.withValues(alpha: 0.38),
                      hintColor: AppTheme.textPrimary.withValues(alpha: 0.38),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Container(
                    decoration: BoxDecoration(
                      color: AppTheme.textPrimary.withValues(alpha: 0.05),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: IconButton(
                      icon: Icon(
                        _isListView
                            ? Icons.grid_view_rounded
                            : Icons.view_list_rounded,
                        color: AppTheme.primaryLight,
                      ),
                      onPressed: () =>
                          setState(() => _isListView = !_isListView),
                    ),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: Builder(
                builder: (context) {
                  final deptSet = <String>{};
                  final roleSet = <String>{};
                  for (final u in _users) {
                    final mapU = Map<String, dynamic>.from(u as Map);
                    final group = _groupLabel(mapU).trim();
                    if (group.isNotEmpty) deptSet.add(group);

                    final role =
                        (mapU['system_role_label']?.toString() ??
                                mapU['system_role']?.toString() ??
                                '')
                            .trim();
                    if (role.isNotEmpty) roleSet.add(role);
                  }

                  final deptItems = ['All', ...deptSet.toList()..sort()];
                  final roleItems = ['All', ...roleSet.toList()..sort()];

                  return Row(
                    children: [
                      Expanded(
                        child: _buildSmallFilter(
                          'ផ្នែក',
                          _selectedDept,
                          deptItems,
                          (v) {
                            setState(() {
                              _selectedDept = v!;
                              _onSearch();
                            });
                          },
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: _buildSmallFilter(
                          'តួនាទី',
                          _selectedRole,
                          roleItems,
                          (v) {
                            setState(() {
                              _selectedRole = v!;
                              _onSearch();
                            });
                          },
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: _buildSmallFilter(
                          'ស្ថានភាព',
                          _selectedStatus,
                          ['All', 'Active', 'Suspended'],
                          (v) {
                            setState(() {
                              _selectedStatus = v!;
                              _onSearch();
                            });
                          },
                        ),
                      ),
                    ],
                  );
                },
              ),
            ),
            Expanded(
              child: _isLoading
                  ? _buildShimmerGrid()
                  : _filtered.isEmpty
                  ? Center(
                      child: Text(
                        "មិនមានទិន្នន័យ",
                        style: TextStyle(
                          color: AppTheme.textPrimary.withValues(alpha: 0.38),
                        ),
                      ),
                    )
                  : _buildGroupedList(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildShimmerGrid() {
    return GridView.builder(
      padding: const EdgeInsets.all(16),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
        childAspectRatio: 0.8,
      ),
      itemCount: 8,
      itemBuilder: (context, index) => AppShimmer(
        child: Container(
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(20),
          ),
        ),
      ),
    );
  }

  Widget _buildGroupedList() {
    final Map<String, List<Map<String, dynamic>>> grouped = {};
    for (final u in _filtered) {
      final user = Map<String, dynamic>.from(u as Map);
      final key = _groupLabel(user);
      grouped.putIfAbsent(key, () => []).add(user);
    }

    final keys = grouped.keys.toList()
      ..sort((a, b) {
        if (a == 'Other' && b != 'Other') return 1;
        if (b == 'Other' && a != 'Other') return -1;
        return a.toLowerCase().compareTo(b.toLowerCase());
      });

    int animIndex = 0;
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      children: [
        for (final key in keys) ...[
          const SizedBox(height: 6),
          _buildGroupHeader(key, grouped[key]!.length),
          const SizedBox(height: 10),
          LayoutBuilder(
            builder: (context, constraints) {
              if (_isListView) {
                return Column(
                  children: grouped[key]!.map((user) {
                    return AppUserListTile(
                      user: user,
                      index: animIndex++,
                      onTap: () => _editUser(user),
                      trailingAction: _buildActionMenu(user),
                    );
                  }).toList(),
                );
              } else {
                final double cardWidth = (constraints.maxWidth - 12) / 2;
                return Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  alignment: WrapAlignment.center,
                  children: grouped[key]!.map((user) {
                    return SizedBox(
                      width: cardWidth,
                      child: AppUserCard(
                        user: user,
                        index: animIndex++,
                        onTap: () => _editUser(user),
                        trailingAction: _buildActionMenu(user),
                      ),
                    );
                  }).toList(),
                );
              }
            },
          ),
          const SizedBox(height: 16),
        ],
      ],
    );
  }

  Widget _buildGroupHeader(String title, int count) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.textPrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.08)),
      ),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: AppTheme.primary,
              borderRadius: BorderRadius.circular(12),
              boxShadow: AppTheme.primaryShadow,
            ),
            child: Icon(
              Icons.apartment_rounded,
              color: AppTheme.textPrimary,
              size: 18,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              title,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: AppTheme.primary.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(999),
              border: Border.all(
                color: AppTheme.primary.withValues(alpha: 0.25),
              ),
            ),
            child: Text(
              '$count',
              style: GoogleFonts.inter(
                color: AppTheme.primaryLight,
                fontSize: 11,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSmallFilter(
    String hint,
    String value,
    List<String> items,
    Function(String?) onChanged,
  ) {
    return Container(
      height: 38,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        color: AppTheme.textPrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(12),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String>(
          value: items.contains(value) ? value : items.first,
          isExpanded: true,
          dropdownColor: const Color(0xFF2E2E3E),
          icon: Icon(
            Icons.arrow_drop_down,
            color: AppTheme.textPrimary.withValues(alpha: 0.5),
          ),
          style: TextStyle(color: AppTheme.textPrimary, fontSize: 12),
          items: items
              .map(
                (e) => DropdownMenuItem(
                  value: e,
                  child: Text(e, maxLines: 1, overflow: TextOverflow.ellipsis),
                ),
              )
              .toList(),
          onChanged: onChanged,
        ),
      ),
    );
  }

  Widget _buildActionMenu(Map<String, dynamic> user) {
    return PopupMenuButton<String>(
      icon: Icon(
        Icons.more_vert_rounded,
        color: AppTheme.textPrimary.withValues(alpha: 0.5),
        size: 20,
      ),
      color: const Color(0xFF2E2E3E),
      onSelected: (val) {
        if (val == 'edit') _editUser(user);
        if (val == 'delete') _deleteUser(user['employee_id']);
        if (val == 'suspend') {
          /* Call suspend block here */
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('មុខងារ Suspended នឹងមានឆាប់ៗនេះ')),
          );
        }
      },
      itemBuilder: (context) => [
        PopupMenuItem(
          value: 'edit',
          child: Row(
            children: [
              Icon(Icons.edit, size: 18, color: AppTheme.textPrimary),
              const SizedBox(width: 8),
              Text('កែប្រែ', style: TextStyle(color: AppTheme.textPrimary)),
            ],
          ),
        ),
        PopupMenuItem(
          value: 'suspend',
          child: Row(
            children: [
              const Icon(Icons.block, size: 18, color: Colors.orange),
              const SizedBox(width: 8),
              Text('ផ្អាក', style: TextStyle(color: AppTheme.textPrimary)),
            ],
          ),
        ),
        PopupMenuItem(
          value: 'delete',
          child: Row(
            children: [
              const Icon(Icons.delete, size: 18, color: Colors.redAccent),
              const SizedBox(width: 8),
              Text('លុប', style: TextStyle(color: Colors.redAccent)),
            ],
          ),
        ),
      ],
    );
  }

  void _editUser(Map<String, dynamic>? user) {
    final isEdit = user != null;
    final nameCtrl = TextEditingController(text: user?['name'] ?? '');
    final eidCtrl = TextEditingController(text: user?['employee_id'] ?? '');
    final passCtrl = TextEditingController();
    final deptCtrl = TextEditingController(text: user?['department'] ?? '');
    final posCtrl = TextEditingController(text: user?['position'] ?? '');
    final branchCtrl = TextEditingController(text: user?['branch'] ?? '');
    String sysRole = user?['system_role'] ?? 'Employee';

    // Full Info Fields
    final latinNameCtrl = TextEditingController(
      text: user?['latin_name'] ?? '',
    );
    final usernameCtrl = TextEditingController(text: user?['username'] ?? '');
    final emailCtrl = TextEditingController(text: user?['email'] ?? '');
    final addressCtrl = TextEditingController(
      text: user?['current_address'] ?? '',
    );
    final joinedAtCtrl = TextEditingController(text: user?['joined_at'] ?? '');
    final baseSalaryCtrl = TextEditingController(
      text: (user?['base_salary'] ?? 0.0).toString(),
    );
    final nssfIdCtrl = TextEditingController(text: user?['nssf_id'] ?? '');
    String maritalStatus = user?['marital_status'] ?? 'Single';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => StatefulBuilder(
        builder: (context, setModalState) => DefaultTabController(
          length: 3,
          child: Container(
            height: MediaQuery.of(context).size.height * 0.85,
            decoration: const BoxDecoration(
              color: Color(0xFF1E1E2E),
              borderRadius: BorderRadius.vertical(top: Radius.circular(30)),
            ),
            child: Column(
              children: [
                const SizedBox(height: 12),
                Container(
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Colors.white24,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                const SizedBox(height: 12),
                TabBar(
                  dividerColor: Colors.transparent,
                  indicatorColor: AppTheme.primary,
                  labelStyle: GoogleFonts.kantumruyPro(
                    fontWeight: FontWeight.bold,
                    fontSize: 13,
                  ),
                  unselectedLabelStyle: GoogleFonts.kantumruyPro(fontSize: 13),
                  tabs: const [
                    Tab(text: "មូលដ្ឋាន"),
                    Tab(text: "បុគ្គលិក"),
                    Tab(text: "Payroll"),
                  ],
                ),
                Expanded(
                  child: TabBarView(
                    children: [
                      SingleChildScrollView(
                        padding: const EdgeInsets.all(20),
                        child: Column(
                          children: [
                            Row(
                              children: [
                                Expanded(
                                  child: _buildField(
                                    "ID*",
                                    eidCtrl,
                                    enabled: !isEdit,
                                  ),
                                ),
                                const SizedBox(width: 12),
                                Expanded(
                                  flex: 2,
                                  child: _buildField("ឈ្មោះ*", nameCtrl),
                                ),
                              ],
                            ),
                            _buildField("ឈ្មោះឡាតាំង", latinNameCtrl),
                            _buildField("Username*", usernameCtrl),
                            _buildField("Email*", emailCtrl),
                            _buildField(
                              "លេខសម្ងាត់",
                              passCtrl,
                              isPass: true,
                              hint: isEdit
                                  ? "•••••••• (Keep empty to keep)"
                                  : "123456",
                            ),
                          ],
                        ),
                      ),
                      SingleChildScrollView(
                        padding: const EdgeInsets.all(20),
                        child: Column(
                          children: [
                            Row(
                              children: [
                                Expanded(child: _buildField("ផ្នែក", deptCtrl)),
                                const SizedBox(width: 12),
                                Expanded(child: _buildField("តួនាទី", posCtrl)),
                              ],
                            ),
                            _buildField("សាខា", branchCtrl),
                            _buildDropdownField(
                              "សិទ្ធិក្នុងប្រព័ន្ធ",
                              sysRole,
                              (v) {
                                if (v != null) setModalState(() => sysRole = v);
                              },
                            ),
                            _buildField(
                              "កាលបរិច្ឆេទចូលធ្វើការ",
                              joinedAtCtrl,
                              hint: "YYYY-MM-DD",
                            ),
                            _buildField("អាសយដ្ឋានបច្ចុប្បន្ន", addressCtrl),
                          ],
                        ),
                      ),
                      SingleChildScrollView(
                        padding: const EdgeInsets.all(20),
                        child: Column(
                          children: [
                            _buildField("ប្រាក់ខែគោល (\$)", baseSalaryCtrl),
                            _buildField("លេខប័ណ្ណ ប.ស.ស", nssfIdCtrl),
                            _buildDropdownField(
                              "ស្ថានភាពគ្រួសារ",
                              maritalStatus,
                              (v) {
                                if (v != null) {
                                  setModalState(() => maritalStatus = v);
                                }
                              },
                              items: ['Single', 'Married', 'Divorced'],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Row(
                    children: [
                      if (isEdit)
                        Expanded(
                          child: OutlinedButton(
                            onPressed: () => _deleteUser(user['employee_id']),
                            style: OutlinedButton.styleFrom(
                              padding: const EdgeInsets.symmetric(vertical: 16),
                              side: BorderSide(
                                color: Colors.redAccent.withValues(alpha: 0.5),
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(16),
                              ),
                            ),
                            child: Text(
                              "លុប",
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.redAccent,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                      if (isEdit) const SizedBox(width: 12),
                      Expanded(
                        flex: 2,
                        child: ElevatedButton(
                          onPressed: () => _saveUser(
                            context,
                            eidCtrl.text,
                            nameCtrl.text,
                            sysRole,
                            passCtrl.text,
                            deptCtrl.text,
                            posCtrl.text,
                            branchCtrl.text,
                            latinName: latinNameCtrl.text,
                            username: usernameCtrl.text,
                            email: emailCtrl.text,
                            address: addressCtrl.text,
                            joinedAt: joinedAtCtrl.text,
                            maritalStatus: maritalStatus,
                            baseSalary:
                                double.tryParse(baseSalaryCtrl.text) ?? 0.0,
                            nssfId: nssfIdCtrl.text,
                          ),
                          style: ElevatedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(vertical: 16),
                            backgroundColor: AppTheme.primary,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(16),
                            ),
                            elevation: 0,
                          ),
                          child: Text(
                            "រក្សាទុក",
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDropdownField(
    String label,
    String value,
    Function(String?) onChanged, {
    List<String>? items,
  }) {
    final isSystemRoleDropdown = items == null;
    final list = items ?? appSystemRoleValues;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary.withValues(alpha: 0.70),
            fontSize: 13,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          height: 52,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          decoration: BoxDecoration(
            color: AppTheme.textPrimary.withValues(alpha: 0.05),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: AppTheme.textPrimary.withValues(alpha: 0.05),
            ),
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<String>(
              value: list.contains(value) ? value : list.first,
              isExpanded: true,
              dropdownColor: const Color(0xFF2E2E3E),
              icon: Icon(
                Icons.keyboard_arrow_down_rounded,
                color: AppTheme.textPrimary.withValues(alpha: 0.54),
              ),
              style: TextStyle(color: AppTheme.textPrimary, fontSize: 14),
              items: list
                  .map(
                    (e) => DropdownMenuItem(
                      value: e,
                      child: Text(
                        isSystemRoleDropdown
                            ? appSystemRoleDisplayLabel(e)
                            : e,
                      ),
                    ),
                  )
                  .toList(),
              onChanged: onChanged,
            ),
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  Widget _buildField(
    String label,
    TextEditingController ctrl, {
    bool enabled = true,
    bool isPass = false,
    String? hint,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary.withValues(alpha: 0.70),
            fontSize: 13,
          ),
        ),
        const SizedBox(height: 8),
        SizedBox(
          height: 52,
          child: TextField(
            controller: ctrl,
            enabled: enabled,
            obscureText: isPass,
            style: TextStyle(
              color: enabled
                  ? AppTheme.textPrimary
                  : AppTheme.textPrimary.withValues(alpha: 0.54),
              fontSize: 14,
            ),
            decoration: InputDecoration(
              hintText: hint,
              hintStyle: TextStyle(
                color: AppTheme.textPrimary.withValues(alpha: 0.24),
                fontSize: 14,
              ),
              filled: true,
              fillColor: enabled
                  ? AppTheme.textPrimary.withValues(alpha: 0.05)
                  : AppTheme.textPrimary.withValues(alpha: 0.02),
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 0,
              ),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(16),
                borderSide: BorderSide.none,
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(16),
                borderSide: BorderSide.none,
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(16),
                borderSide: BorderSide(color: AppTheme.primary),
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  Future<void> _saveUser(
    BuildContext context,
    String eid,
    String name,
    String role,
    String pass,
    String dept,
    String pos,
    String branch, {
    String? latinName,
    String? username,
    String? email,
    String? address,
    String? joinedAt,
    String? maritalStatus,
    double? baseSalary,
    String? nssfId,
  }) async {
    if (eid.isEmpty || name.isEmpty) return;
    Navigator.pop(context);
    setState(() => _isLoading = true);
    try {
      final res = await _api.saveUser(
        targetEid: eid,
        name: name,
        systemRole: role,
        password: pass,
        department: dept,
        position: pos,
        branch: branch,
        latinName: latinName,
        username: username,
        email: email,
        address: address,
        joinedAt: joinedAt,
        maritalStatus: maritalStatus,
        baseSalary: baseSalary,
        nssfId: nssfId,
      );
      if (!mounted) return;
      if (res['success'] == true) {
        _loadUsers();
      } else {
        _showError(res['message'] ?? 'Failed to save');
      }
    } catch (e) {
      if (!mounted) return;
      _showError('Error: $e');
    }
  }

  Future<void> _deleteUser(String eid) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text("បញ្ជាក់ការលុប"),
        content: Text("តើអ្នកពិតជាចង់លុបបុគ្គលិក $eid មែនទេ?"),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text("បោះបង់"),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text("លុប", style: TextStyle(color: Colors.redAccent)),
          ),
        ],
      ),
    );
    if (!mounted || confirm != true) return;
    Navigator.pop(context);
    setState(() => _isLoading = true);
    try {
      final res = await _api.deleteUser(eid);
      if (!mounted) return;
      if (res['success'] == true) {
        _loadUsers();
      } else {
        _showError(res['message'] ?? 'Failed to delete');
      }
    } catch (e) {
      if (!mounted) return;
      _showError('Error: $e');
    }
  }
}

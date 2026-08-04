import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

// ==========================================
// COLOR PALETTE & DESIGN SYSTEM TOKENS
// ==========================================
class MessengerTheme {
  static const Color bg = Color(0xFFFFFFFF);
  static const Color textPrimary = Color(0xFF000000);
  static const Color textSecondary = Color(0xFF65676B);
  static const Color activeBlue = Color(0xFF0084FF);
  static const Color onlineGreen = Color(0xFF44B700);
  static const Color actionBtnBg = Color(0xFFF0F2F5);
  static const Color adBadgeBg = Color(0xFFE4E6EB);
  static const Color unreadDot = Color(0xFF1084FF);
}

// ==========================================
// DATA MODELS FOR CONVERSATION AND STORIES
// ==========================================
class StoryModel {
  final String id;
  final String firstName;
  final String avatarUrl;
  final bool hasActiveStory;
  final bool isOnline;

  const StoryModel({
    required this.id,
    required this.firstName,
    required this.avatarUrl,
    required this.hasActiveStory,
    required this.isOnline,
  });
}

class ChatModel {
  final String id;
  final String name;
  final String avatarUrl;
  final String lastMessage;
  final String timestamp;
  final bool isUnread;
  final bool isOnline;
  final bool isSentByMe;
  final bool isDelivered;
  final bool isRead;
  final bool isAd;
  final String? adBadgeText;
  final String? adActionText;
  final String? adThumbnailUrl;

  const ChatModel({
    required this.id,
    required this.name,
    required this.avatarUrl,
    required this.lastMessage,
    required this.timestamp,
    this.isUnread = false,
    this.isOnline = false,
    this.isSentByMe = false,
    this.isDelivered = false,
    this.isRead = false,
    this.isAd = false,
    this.adBadgeText,
    this.adActionText,
    this.adThumbnailUrl,
  });
}

// ==========================================
// MAIN WIDGET: MESSENGER HOME SCREEN
// ==========================================
class MessengerHomeScreen extends StatefulWidget {
  const MessengerHomeScreen({super.key});

  @override
  State<MessengerHomeScreen> createState() => _MessengerHomeScreenState();
}

class _MessengerHomeScreenState extends State<MessengerHomeScreen> {
  int _currentTab = 0;

  // Mock Active Stories List
  final List<StoryModel> _stories = const [
    StoryModel(
      id: 'story_1',
      firstName: 'Sander',
      avatarUrl: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=120&auto=format&fit=crop',
      hasActiveStory: true,
      isOnline: true,
    ),
    StoryModel(
      id: 'story_2',
      firstName: 'Renske',
      avatarUrl: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=120&auto=format&fit=crop',
      hasActiveStory: true,
      isOnline: false,
    ),
    StoryModel(
      id: 'story_3',
      firstName: 'Luc',
      avatarUrl: 'https://images.unsplash.com/photo-1599566150163-29194dcaad36?w=120&auto=format&fit=crop',
      hasActiveStory: false,
      isOnline: true,
    ),
    StoryModel(
      id: 'story_4',
      firstName: 'John',
      avatarUrl: 'https://images.unsplash.com/photo-1580489944761-15a19d654956?w=120&auto=format&fit=crop',
      hasActiveStory: false,
      isOnline: true,
    ),
    StoryModel(
      id: 'story_5',
      firstName: 'Sarah',
      avatarUrl: 'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=120&auto=format&fit=crop',
      hasActiveStory: true,
      isOnline: true,
    ),
  ];

  // Mock Conversations List (including Porsche Sponsored Ad)
  final List<ChatModel> _chats = const [
    ChatModel(
      id: 'chat_1',
      name: 'Sander van Dongen',
      avatarUrl: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=120&auto=format&fit=crop',
      lastMessage: 'Hahaha',
      timestamp: '9:40',
      isUnread: false,
      isOnline: true,
      isRead: true,
    ),
    ChatModel(
      id: 'chat_2',
      name: 'Jorge Rodriguez',
      avatarUrl: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=120&auto=format&fit=crop',
      lastMessage: 'Okay I\'ll see you there!',
      timestamp: '8:43',
      isOnline: true,
      isRead: true,
    ),
    ChatModel(
      id: 'chat_3',
      name: 'Group project',
      avatarUrl: 'https://images.unsplash.com/photo-1522071820081-009f0129c71c?w=120&auto=format&fit=crop',
      lastMessage: 'You: I have a question. Can...',
      timestamp: 'Fri',
      isSentByMe: true,
      isDelivered: true,
    ),
    ChatModel(
      id: 'chat_4',
      name: 'Lauren Turner',
      avatarUrl: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=120&auto=format&fit=crop',
      lastMessage: 'You: I have a question. Can...',
      timestamp: 'Thu',
      isOnline: true,
      isSentByMe: true,
      isDelivered: true,
    ),
    ChatModel(
      id: 'chat_5',
      name: 'Luc van Loon',
      avatarUrl: 'https://images.unsplash.com/photo-1599566150163-29194dcaad36?w=120&auto=format&fit=crop',
      lastMessage: 'That is entirely possible ofc',
      timestamp: 'Thu',
      isRead: true,
    ),
    ChatModel(
      id: 'chat_ad_porsche',
      name: 'Porsche',
      avatarUrl: 'https://images.unsplash.com/photo-1614162692292-7ac56d7f7f1e?w=120&auto=format&fit=crop',
      lastMessage: 'The new Macan',
      timestamp: '',
      isAd: true,
      adBadgeText: 'Ad',
      adActionText: 'មើលបន្ថែម',
      adThumbnailUrl: 'https://images.unsplash.com/photo-1614162692292-7ac56d7f7f1e?w=200&auto=format&fit=crop',
    ),
    ChatModel(
      id: 'chat_6',
      name: 'Cassandra O\'Hara',
      avatarUrl: 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=120&auto=format&fit=crop',
      lastMessage: 'You: I have a question. Can...',
      timestamp: 'Wed',
      isSentByMe: true,
      isDelivered: true,
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MessengerTheme.bg,
      body: SafeArea(
        child: Column(
          children: [
            // A. Top Custom Header Section
            _buildHeader(),
            
            // Search Bar Container
            _buildSearchBar(),
            
            // Expanded List View for Stories and Conversations
            Expanded(
              child: ListView(
                physics: const BouncingScrollPhysics(),
                children: [
                  const SizedBox(height: 12),
                  // B. Active Stories Section
                  _buildStoriesSection(),
                  const SizedBox(height: 16),
                  
                  // C. Main Vertical Chat List
                  _buildChatList(),
                ],
              ),
            ),
            
            // D. Custom Bottom Navigation Bar
            _buildBottomNav(),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // APP HEADER (TOP BAR)
  // ==========================================
  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      child: Row(
        children: [
          // Left Profile Avatar
          const CircleAvatar(
            radius: 20.0,
            backgroundImage: NetworkImage(
              'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop',
            ),
          ),
          const SizedBox(width: 14.0),
          
          // Title "Chats"
          Expanded(
            child: Text(
              'សារ',
              style: GoogleFonts.kantumruyPro(
                fontSize: 26.0,
                fontWeight: FontWeight.bold,
                color: MessengerTheme.textPrimary,
                height: 1.1,
              ),
            ),
          ),
          
          // Right Custom Action Rounded Buttons
          _buildRoundedActionButton(
            icon: Icons.camera_alt_rounded,
            onTap: () {},
          ),
          const SizedBox(width: 12.0),
          _buildRoundedActionButton(
            icon: Icons.edit_rounded,
            onTap: () {},
          ),
        ],
      ),
    );
  }

  Widget _buildRoundedActionButton({required IconData icon, required VoidCallback onTap}) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 36.0,
        height: 36.0,
        decoration: const BoxDecoration(
          color: MessengerTheme.actionBtnBg,
          shape: BoxShape.circle,
        ),
        child: Icon(
          icon,
          size: 20.0,
          color: MessengerTheme.textPrimary,
        ),
      ),
    );
  }

  // ==========================================
  // SEARCH BAR
  // ==========================================
  Widget _buildSearchBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      child: Container(
        height: 38.0,
        decoration: BoxDecoration(
          color: MessengerTheme.actionBtnBg,
          borderRadius: BorderRadius.circular(10.0),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12.0),
        child: Row(
          children: [
            const Icon(
              Icons.search_rounded,
              color: MessengerTheme.textSecondary,
              size: 20.0,
            ),
            const SizedBox(width: 8.0),
            Expanded(
              child: Text(
                'ស្វែងរក',
                style: GoogleFonts.kantumruyPro(
                  color: MessengerTheme.textSecondary,
                  fontSize: 15.0,
                  fontWeight: FontWeight.w400,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // ACTIVE STORIES SECTION (HORIZONTAL)
  // ==========================================
  Widget _buildStoriesSection() {
    return SizedBox(
      height: 94.0,
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 16.0),
        itemCount: _stories.length + 1, // Add 1 for "Your Story" first item
        itemBuilder: (context, index) {
          if (index == 0) {
            // First item: "Your Story" Add item
            return Container(
              margin: const EdgeInsets.only(right: 14.0),
              child: Column(
                children: [
                  Stack(
                    alignment: Alignment.center,
                    children: [
                      Container(
                        width: 58.0,
                        height: 58.0,
                        decoration: BoxDecoration(
                          color: MessengerTheme.actionBtnBg,
                          shape: BoxShape.circle,
                          border: Border.all(
                            color: Colors.grey.shade300,
                            width: 0.8,
                          ),
                        ),
                        child: const Icon(
                          Icons.add_rounded,
                          size: 30.0,
                          color: MessengerTheme.textPrimary,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8.0),
                  SizedBox(
                    width: 62.0,
                    child: Text(
                      'រឿងរបស់អ្នក',
                      textAlign: TextAlign.center,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 12.0,
                        fontWeight: FontWeight.w400,
                        color: MessengerTheme.textSecondary,
                      ),
                    ),
                  ),
                ],
              ),
            );
          }

          final story = _stories[index - 1];
          return Container(
            margin: const EdgeInsets.only(right: 14.0),
            child: Column(
              children: [
                Stack(
                  children: [
                    // Active story circular border setup
                    Container(
                      padding: const EdgeInsets.all(2.5),
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: story.hasActiveStory
                              ? MessengerTheme.activeBlue
                              : Colors.transparent,
                          width: 2.2,
                        ),
                      ),
                      child: CircleAvatar(
                        radius: 24.5,
                        backgroundImage: NetworkImage(story.avatarUrl),
                      ),
                    ),
                    
                    // Bottom-Right Online Dot Indicator
                    if (story.isOnline)
                      Positioned(
                        right: 2.0,
                        bottom: 2.0,
                        child: Container(
                          width: 13.0,
                          height: 13.0,
                          decoration: BoxDecoration(
                            color: MessengerTheme.onlineGreen,
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: Colors.white,
                              width: 2.5,
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
                const SizedBox(height: 8.0),
                SizedBox(
                  width: 62.0,
                  child: Text(
                    story.firstName,
                    textAlign: TextAlign.center,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: GoogleFonts.inter(
                      fontSize: 12.0,
                      fontWeight: story.hasActiveStory
                          ? FontWeight.w600
                          : FontWeight.w400,
                      color: story.hasActiveStory
                          ? MessengerTheme.textPrimary
                          : MessengerTheme.textSecondary,
                    ),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  // ==========================================
  // MAIN CONVERSATION TILE LIST
  // ==========================================
  Widget _buildChatList() {
    return ListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: _chats.length,
      itemBuilder: (context, index) {
        final chat = _chats[index];
        
        if (chat.isAd) {
          return _buildAdTile(chat);
        }
        
        return _buildStandardChatTile(chat);
      },
    );
  }

  Widget _buildStandardChatTile(ChatModel chat) {
    return InkWell(
      onTap: () {},
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            // Left Profile Picture with Status
            Stack(
              children: [
                CircleAvatar(
                  radius: 28.0,
                  backgroundImage: NetworkImage(chat.avatarUrl),
                ),
                if (chat.isOnline)
                  Positioned(
                    right: 0.0,
                    bottom: 0.0,
                    child: Container(
                      width: 15.0,
                      height: 15.0,
                      decoration: BoxDecoration(
                        color: MessengerTheme.onlineGreen,
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: Colors.white,
                          width: 2.5,
                        ),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(width: 14.0),
            
            // Conversation info details
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    chat.name,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 16.0,
                      fontWeight: chat.isUnread ? FontWeight.bold : FontWeight.w600,
                      color: MessengerTheme.textPrimary,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4.0),
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          chat.lastMessage,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 14.0,
                            fontWeight: chat.isUnread ? FontWeight.w800 : FontWeight.normal,
                            color: chat.isUnread
                                ? MessengerTheme.textPrimary
                                : MessengerTheme.textSecondary,
                          ),
                        ),
                      ),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 6.0),
                        child: Text(
                          '•',
                          style: TextStyle(
                            fontSize: 12.0,
                            color: chat.isUnread
                                ? MessengerTheme.textPrimary
                                : MessengerTheme.textSecondary,
                          ),
                        ),
                      ),
                      Text(
                        chat.timestamp,
                        style: GoogleFonts.inter(
                          fontSize: 14.0,
                          fontWeight: chat.isUnread ? FontWeight.w700 : FontWeight.normal,
                          color: chat.isUnread
                              ? MessengerTheme.textPrimary
                              : MessengerTheme.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            
            // Read/Sent indicator
            _buildTrailingStatus(chat),
          ],
        ),
      ),
    );
  }

  Widget _buildTrailingStatus(ChatModel chat) {
    if (chat.isUnread) {
      return Container(
        width: 12.0,
        height: 12.0,
        decoration: const BoxDecoration(
          color: MessengerTheme.unreadDot,
          shape: BoxShape.circle,
        ),
      );
    }
    
    if (chat.isSentByMe) {
      if (chat.isDelivered) {
        return Container(
          width: 14.0,
          height: 14.0,
          decoration: BoxDecoration(
            color: Colors.grey.shade200,
            shape: BoxShape.circle,
          ),
          child: const Icon(
            Icons.check,
            size: 10.0,
            color: Colors.black45,
          ),
        );
      }
      return Container(
        width: 14.0,
        height: 14.0,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          border: Border.all(color: Colors.grey.shade400, width: 1.0),
        ),
      );
    }

    if (chat.isRead) {
      return Container(
        width: 14.0,
        height: 14.0,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          border: Border.all(color: Colors.grey.shade300, width: 1.0),
        ),
        child: const Icon(
          Icons.check,
          size: 10.0,
          color: Colors.black26,
        ),
      );
    }

    return const SizedBox.shrink();
  }

  // ==========================================
  // SPONSORED / AD CONVERSATION TILE
  // ==========================================
  Widget _buildAdTile(ChatModel chat) {
    return InkWell(
      onTap: () {},
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            // Left brand Avatar
            CircleAvatar(
              radius: 28.0,
              backgroundColor: const Color(0xFFF9FAFB),
              child: ClipOval(
                child: Image.network(
                  chat.avatarUrl,
                  width: 56.0,
                  height: 56.0,
                  fit: BoxFit.cover,
                ),
              ),
            ),
            const SizedBox(width: 14.0),
            
            // Ad Campaign Details
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        chat.name,
                        style: GoogleFonts.inter(
                          fontSize: 16.0,
                          fontWeight: FontWeight.bold,
                          color: MessengerTheme.textPrimary,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(width: 6.0),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 5.0, vertical: 1.8),
                        decoration: BoxDecoration(
                          color: MessengerTheme.adBadgeBg,
                          borderRadius: BorderRadius.circular(4.0),
                        ),
                        child: Text(
                          chat.adBadgeText ?? 'Ad',
                          style: GoogleFonts.inter(
                            fontSize: 10.0,
                            fontWeight: FontWeight.w700,
                            color: MessengerTheme.textSecondary,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4.0),
                  Text(
                    chat.lastMessage,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 14.0,
                      color: MessengerTheme.textSecondary,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2.0),
                  GestureDetector(
                    onTap: () {},
                    child: Text(
                      chat.adActionText ?? 'មើលបន្ថែម',
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 14.0,
                        fontWeight: FontWeight.bold,
                        color: MessengerTheme.activeBlue,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8.0),
            
            // Ad Image Thumbnail
            if (chat.adThumbnailUrl != null)
              ClipRRect(
                borderRadius: BorderRadius.circular(10.0),
                child: Image.network(
                  chat.adThumbnailUrl!,
                  width: 52.0,
                  height: 52.0,
                  fit: BoxFit.cover,
                ),
              ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // STICKY BOTTOM BAR (TABS)
  // ==========================================
  Widget _buildBottomNav() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white,
        border: Border(
          top: BorderSide(
            color: Colors.grey.shade200,
            width: 0.6,
          ),
        ),
      ),
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          // Tab 1: Chats (Active)
          Expanded(
            child: GestureDetector(
              onTap: () => setState(() => _currentTab = 0),
              behavior: HitTestBehavior.opaque,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.chat_bubble_rounded,
                    color: _currentTab == 0 ? Colors.black : Colors.grey.shade400,
                    size: 24.0,
                  ),
                  const SizedBox(height: 4.0),
                  Text(
                    'សារ',
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 12.0,
                      fontWeight: _currentTab == 0 ? FontWeight.w700 : FontWeight.w500,
                      color: _currentTab == 0 ? Colors.black : Colors.grey.shade500,
                    ),
                  ),
                ],
              ),
            ),
          ),
          
          // Tab 2: People (Inactive + Badge notification Count)
          Expanded(
            child: GestureDetector(
              onTap: () => setState(() => _currentTab = 1),
              behavior: HitTestBehavior.opaque,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Stack(
                    clipBehavior: Clip.none,
                    children: [
                      Icon(
                        Icons.people_alt_rounded,
                        color: _currentTab == 1 ? Colors.black : Colors.grey.shade400,
                        size: 24.0,
                      ),
                      // Notification pill overlay
                      Positioned(
                        top: -4.0,
                        right: -10.0,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 5.0, vertical: 1.5),
                          decoration: BoxDecoration(
                            color: Colors.green.shade600,
                            borderRadius: BorderRadius.circular(10.0),
                          ),
                          child: const Text(
                            '46',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 9.0,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4.0),
                  Text(
                    'មនុស្ស',
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 12.0,
                      fontWeight: _currentTab == 1 ? FontWeight.w700 : FontWeight.w500,
                      color: _currentTab == 1 ? Colors.black : Colors.grey.shade500,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

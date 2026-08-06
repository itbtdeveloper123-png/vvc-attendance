import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// ប្រភេទនៃសារនៅក្នុង Chat
enum MessageType {
  text,
  voice,
  image,
  emoji,
}

/// ម៉ូឌែលទិន្នន័យសម្រាប់សារនីមួយៗ
class ChatMessage {
  final String text;
  final bool isSent; // true បើសារផ្ញើចេញ (ខាងស្តាំ), false បើសារទទួល (ខាងឆ្វេង)
  final String time;
  final MessageType type;
  final String? voiceDuration;
  final String? imageUrl;
  final bool isRead;

  ChatMessage({
    required this.text,
    required this.isSent,
    required this.time,
    this.type = MessageType.text,
    this.voiceDuration,
    this.imageUrl,
    this.isRead = true,
  });
}

/// អេក្រង់ជជែកបែប Frosted Glass (Telegram Look)
class TelegramFrostedChatScreen extends StatelessWidget {
  const TelegramFrostedChatScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // បង្កើតទិន្នន័យគំរូសម្រាប់សារ (Sample Messages) ស្រដៀងនឹងរូបភាពគំរូ
    final List<dynamic> items = [
      ChatMessage(
        text: "👍",
        isSent: true,
        time: "8:28 AM",
        type: MessageType.emoji,
      ),
      ChatMessage(
        text: "👍",
        isSent: true,
        time: "8:28 AM",
        type: MessageType.emoji,
      ),
      "ថ្ងៃនេះ (Today)", // កាលបរិច្ឆេទ Divider
      ChatMessage(
        text: "",
        isSent: false,
        time: "1:07 PM",
        type: MessageType.voice,
        voiceDuration: "0:03",
      ),
      ChatMessage(
        text: "",
        isSent: true,
        time: "1:07 PM",
        type: MessageType.image,
        imageUrl: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=500&auto=format&fit=crop&q=80",
      ),
      ChatMessage(
        text: "សួស្តីបង! តើការងារថ្ងៃនេះយ៉ាងម៉េចដែរ?",
        isSent: false,
        time: "1:10 PM",
      ),
      ChatMessage(
        text: "បាទបង! ខ្ញុំបានរៀបចំរបាយការណ៍ និងផ្ញើទៅកាន់ប្រព័ន្ធរួចរាល់ហើយ។",
        isSent: true,
        time: "1:12 PM",
      ),
      ChatMessage(
        text: "ល្អណាស់! អរគុណច្រើនសម្រាប់ការខិតខំប្រឹងប្រែង។",
        isSent: false,
        time: "1:15 PM",
      ),
    ];

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A), // ពណ៌ផ្ទៃក្រោយចម្បង (Dark fallback)
      body: Stack(
        children: [
          // 1. Background Layer: ផ្ទៃខាងក្រោយដែលមានរូបភាព Wallpaper និង gradient overlay
          Positioned.fill(
            child: Container(
              decoration: const BoxDecoration(
                image: DecorationImage(
                  image: AssetImage('assets/wallpapers/01.jpg'), // ប្រើប្រាស់ wallpaper រូបភាពពី assets
                  fit: BoxFit.cover,
                  // បន្ថែម overlay ដើម្បីឱ្យផ្ទៃខាងក្រោយមានភាពទាក់ទាញ និងស្រទន់
                  colorFilter: ColorFilter.mode(
                    Color(0xFF2E1A47), // ពណ៌ស្វាយចាស់បែប Telegram
                    BlendMode.color,
                  ),
                ),
              ),
              child: Container(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      const Color(0xFF1E112C).withOpacity(0.85),
                      const Color(0xFF0F081D).withOpacity(0.92),
                    ],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  ),
                ),
              ),
            ),
          ),

          // 2. Content Layer (Chat Bubbles): បញ្ជីសារជជែក ListView.builder
          Positioned.fill(
            child: ListView.builder(
              physics: const BouncingScrollPhysics(),
              // កំណត់ clipBehavior ទៅ Clip.none ដើម្បីឱ្យសារបង្ហាញខ្លួននៅក្រោមរបារកញ្ចក់ព្រាលពេលរំកិល
              clipBehavior: Clip.none,
              // បន្ថែម padding ខាងលើ និងខាងក្រោមដើម្បីការពារកុំឱ្យបាំងរបារ Top & Bottom ពេលនៅស្ងៀម
              padding: EdgeInsets.only(
                top: MediaQuery.of(context).padding.top + 76.0,
                bottom: MediaQuery.of(context).padding.bottom + 85.0,
                left: 14.0,
                right: 14.0,
              ),
              itemCount: items.length,
              itemBuilder: (context, index) {
                final item = items[index];

                // បង្ហាញ Divider ប្រសិនបើជាអក្សរកាលបរិច្ឆេទ
                if (item is String) {
                  return _buildDateDivider(item);
                }

                // បង្ហាញ Chat Bubble ប្រសិនបើជា ChatMessage
                final message = item as ChatMessage;
                return _buildChatBubble(context, message);
              },
            ),
          ),

          // 3. Fixed Top Header (Frosted Glass Effect)
          Positioned(
            top: 0,
            left: 0,
            right: 0,
            child: _buildFrostedTopBar(context),
          ),

          // 4. Fixed Bottom Input Bar (Frosted Glass Effect)
          Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            child: _buildFrostedBottomInput(context),
          ),
        ],
      ),
    );
  }

  /// របារខាងលើបែបកញ្ចក់ព្រាល (Frosted Glass AppBar)
  Widget _buildFrostedTopBar(BuildContext context) {
    final double statusBarHeight = MediaQuery.of(context).padding.top;

    return ClipRRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 20.0, sigmaY: 20.0), // កម្រិតព្រាល
        child: Container(
          width: double.infinity,
          padding: EdgeInsets.only(
            top: statusBarHeight + 8.0,
            bottom: 12.0,
            left: 16.0,
            right: 16.0,
          ),
          // ការរួមបញ្ចូលគ្នារវាង BackdropFilter និងការលាបពណ៌ខ្មៅស្រាល ដើម្បីបង្កើត Telegram Clean Look
          color: Colors.black.withOpacity(0.65),
          child: Row(
            children: [
              // ប៊ូតុងត្រឡប់ក្រោយ (Back Button) រចនាបថរាងមូលស្រាល
              GestureDetector(
                onTap: () => Navigator.maybePop(context),
                child: Container(
                  padding: const EdgeInsets.all(8.0),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: Colors.white.withOpacity(0.12),
                  ),
                  child: const Icon(
                    Icons.arrow_back_ios_new_rounded,
                    color: Colors.white,
                    size: 18.0,
                  ),
                ),
              ),
              const SizedBox(width: 12.0),

              // របារព័ត៌មានកណ្តាល (Profile Pill) រាងពងក្រពើស្អាត
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 6.0, horizontal: 16.0),
                  decoration: BoxDecoration(
                    color: Colors.black.withOpacity(0.35),
                    borderRadius: BorderRadius.circular(20.0),
                    border: Border.all(
                      color: Colors.white.withOpacity(0.08),
                      width: 0.8,
                    ),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        "អាឈី",
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 16.0,
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 2.0),
                      Text(
                        "last seen recently",
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 11.5,
                          color: Colors.white60,
                        ),
                        textAlign: TextAlign.center,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 12.0),

              // CircleAvatar រូបថតអ្នកប្រើប្រាស់ (Profile Image)
              Container(
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: Colors.white.withOpacity(0.15),
                    width: 1.5,
                  ),
                ),
                child: const CircleAvatar(
                  radius: 20.0,
                  backgroundColor: Colors.purple,
                  backgroundImage: NetworkImage(
                    'https://images.unsplash.com/photo-1539571696357-5a69c17a67c6?w=200&auto=format&fit=crop&q=80',
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// របារបញ្ចូលសារខាងក្រោមបែបកញ្ចក់ព្រាល (Frosted Glass Input Bar)
  Widget _buildFrostedBottomInput(BuildContext context) {
    final double bottomPadding = MediaQuery.of(context).padding.bottom;

    return ClipRRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 20.0, sigmaY: 20.0), // កម្រិតព្រាល
        child: Container(
          padding: EdgeInsets.only(
            top: 10.0,
            bottom: bottomPadding > 0 ? bottomPadding + 6.0 : 12.0,
            left: 14.0,
            right: 14.0,
          ),
          color: Colors.black.withOpacity(0.65), // ពណ៌ overlay ដូចរបារខាងលើ
          child: Row(
            children: [
              // ប៊ូតុងភ្ជាប់ឯកសារ (Paperclip Icon)
              GestureDetector(
                onTap: () {},
                child: Container(
                  padding: const EdgeInsets.all(10.0),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: Colors.white.withOpacity(0.1),
                  ),
                  child: const Icon(
                    Icons.attach_file_rounded,
                    color: Colors.white70,
                    size: 22.0,
                  ),
                ),
              ),
              const SizedBox(width: 10.0),

              // ប្រអប់អត្ថបទបញ្ចូលសារ (TextField Container)
              Expanded(
                child: Container(
                  height: 44.0,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(22.0),
                    color: Colors.black.withOpacity(0.3),
                    border: Border.all(
                      color: Colors.white.withOpacity(0.1),
                      width: 0.8,
                    ),
                  ),
                  child: Row(
                    children: [
                      const SizedBox(width: 16.0),
                      Expanded(
                        child: TextField(
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 14.5,
                          ),
                          decoration: InputDecoration(
                            hintText: "Message",
                            hintStyle: GoogleFonts.kantumruyPro(
                              color: Colors.white38,
                              fontSize: 14.5,
                            ),
                            border: InputBorder.none,
                            contentPadding: const EdgeInsets.symmetric(vertical: 10.0),
                          ),
                        ),
                      ),
                      // ប៊ូតុង Emoji / Sticker នៅខាងស្តាំនៃប្រអប់បញ្ចូល
                      IconButton(
                        icon: const Icon(
                          Icons.sticky_note_2_outlined,
                          color: Colors.white54,
                          size: 20.0,
                        ),
                        onPressed: () {},
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 10.0),

              // ប៊ូតុងស្រូបសំឡេង (Microphone Icon)
              GestureDetector(
                onTap: () {},
                child: Container(
                  padding: const EdgeInsets.all(10.0),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: Colors.white.withOpacity(0.1),
                  ),
                  child: const Icon(
                    Icons.mic_none_rounded,
                    color: Colors.white70,
                    size: 22.0,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// របារបែងចែកកាលបរិច្ឆេទ (Date Divider Widget)
  Widget _buildDateDivider(String dateText) {
    return Center(
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 16.0),
        padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 5.0),
        decoration: BoxDecoration(
          color: Colors.black.withOpacity(0.3),
          borderRadius: BorderRadius.circular(12.0),
        ),
        child: Text(
          dateText,
          style: GoogleFonts.kantumruyPro(
            color: Colors.white70,
            fontSize: 12.0,
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
    );
  }

  /// សមាសភាគបង្ហាញប្រអប់សារ (Chat Bubble Widget Builder)
  Widget _buildChatBubble(BuildContext context, ChatMessage message) {
    // ករណីជា Emoji សុទ្ធ (ដូចជាមេដៃ 👍) មិនត្រូវបង្ហាញប្រអប់ព័ទ្ធជុំវិញទេ
    if (message.type == MessageType.emoji) {
      return Align(
        alignment: message.isSent ? Alignment.centerRight : Alignment.centerLeft,
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 4.0),
          padding: const EdgeInsets.symmetric(horizontal: 8.0),
          child: Text(
            message.text,
            style: TextStyle(
              fontSize: 48.0,
              shadows: [
                Shadow(
                  blurRadius: 10.0,
                  color: Colors.black.withOpacity(0.3),
                  offset: const Offset(0, 3),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return Align(
      alignment: message.isSent ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4.0),
        // កំណត់ទំហំអតិបរមារបស់ប្រអប់សារស្មើនឹង 75% នៃទទឹងអេក្រង់
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.75,
        ),
        decoration: BoxDecoration(
          gradient: message.isSent
              ? const LinearGradient(
                  colors: [
                    Color(0xFF8B5CF6), // ពណ៌ស្វាយស្អាត
                    Color(0xFF6D28D9),
                  ],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                )
              : LinearGradient(
                  colors: [
                    const Color(0xFFFCA5A5).withOpacity(0.85), // ពណ៌ផ្កាឈូក/ត្រីសាម៉ុងស្រាល
                    const Color(0xFFF87171).withOpacity(0.9),
                  ],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
          borderRadius: message.isSent
              ? const BorderRadius.only(
                  topLeft: Radius.circular(16.0),
                  topRight: Radius.circular(16.0),
                  bottomLeft: Radius.circular(16.0),
                  bottomRight: Radius.circular(4.0),
                )
              : const BorderRadius.only(
                  topLeft: Radius.circular(16.0),
                  topRight: Radius.circular(16.0),
                  bottomRight: Radius.circular(16.0),
                  bottomLeft: Radius.circular(4.0),
                ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.12),
              blurRadius: 6.0,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: ClipRRect(
          borderRadius: message.isSent
              ? const BorderRadius.only(
                  topLeft: Radius.circular(16.0),
                  topRight: Radius.circular(16.0),
                  bottomLeft: Radius.circular(16.0),
                  bottomRight: Radius.circular(4.0),
                )
              : const BorderRadius.only(
                  topLeft: Radius.circular(16.0),
                  topRight: Radius.circular(16.0),
                  bottomRight: Radius.circular(16.0),
                  bottomLeft: Radius.circular(4.0),
                ),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12.0, vertical: 8.0),
            child: _buildBubbleContent(message),
          ),
        ),
      ),
    );
  }

  /// រៀបចំមាតិកាខាងក្នុងប្រអប់សារអាស្រ័យតាមប្រភេទសារ
  Widget _buildBubbleContent(ChatMessage message) {
    final textStyle = GoogleFonts.kantumruyPro(
      color: message.isSent ? Colors.white : const Color(0xFF1E293B),
      fontSize: 14.5,
      height: 1.35,
    );

    final timeStyle = TextStyle(
      color: message.isSent ? Colors.white60 : Colors.black45,
      fontSize: 10.0,
    );

    // ១. សារជាសំឡេង (Voice Message)
    if (message.type == MessageType.voice) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              // ប៊ូតុង Play
              Container(
                padding: const EdgeInsets.all(6.0),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: message.isSent ? Colors.white24 : Colors.red.shade800.withOpacity(0.85),
                ),
                child: const Icon(
                  Icons.play_arrow_rounded,
                  color: Colors.white,
                  size: 20.0,
                ),
              ),
              const SizedBox(width: 8.0),

              // Waveform Visualizer គំរូដ៏ស្រស់ស្អាត
              Row(
                mainAxisSize: MainAxisSize.min,
                children: List.generate(20, (index) {
                  // កម្ពស់ផ្សេងៗគ្នាសម្រាប់គំនូស waveform
                  final double barHeight = (index % 3 == 0)
                      ? 14.0
                      : (index % 5 == 0)
                          ? 22.0
                          : (index % 2 == 0)
                              ? 6.0
                              : 18.0;
                  final bool isPlayed = index < 8; // សន្មតថាចាក់បានមួយផ្នែក
                  return Container(
                    margin: const EdgeInsets.symmetric(horizontal: 1.0),
                    width: 2.0,
                    height: barHeight,
                    decoration: BoxDecoration(
                      color: isPlayed
                          ? (message.isSent ? Colors.white : Colors.red.shade900)
                          : (message.isSent ? Colors.white30 : Colors.red.shade300.withOpacity(0.5)),
                      borderRadius: BorderRadius.circular(1.0),
                    ),
                  );
                }),
              ),
              const SizedBox(width: 8.0),

              // រយៈពេល និងល្បឿន
              Text(
                message.voiceDuration ?? "0:00",
                style: GoogleFonts.kantumruyPro(
                  color: message.isSent ? Colors.white : const Color(0xFF1E293B),
                  fontWeight: FontWeight.bold,
                  fontSize: 12.0,
                ),
              ),
              const SizedBox(width: 4.0),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 4.0, vertical: 1.0),
                decoration: BoxDecoration(
                  color: message.isSent ? Colors.white12 : Colors.black.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(4.0),
                ),
                child: Text(
                  "1x",
                  style: GoogleFonts.kantumruyPro(
                    color: message.isSent ? Colors.white : const Color(0xFF1E293B),
                    fontWeight: FontWeight.bold,
                    fontSize: 10.0,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4.0),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(message.time, style: timeStyle),
              if (message.isSent) ...[
                const SizedBox(width: 4.0),
                Icon(
                  Icons.done_all_rounded,
                  size: 13.0,
                  color: message.isRead ? Colors.lightBlueAccent : Colors.white60,
                ),
              ]
            ],
          ),
        ],
      );
    }

    // ២. សារជារូបភាព (Image Message)
    if (message.type == MessageType.image) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(12.0),
            child: Stack(
              children: [
                Image.network(
                  message.imageUrl ?? "",
                  width: 240.0,
                  height: 180.0,
                  fit: BoxFit.cover,
                  loadingBuilder: (context, child, loadingProgress) {
                    if (loadingProgress == null) return child;
                    return Container(
                      width: 240.0,
                      height: 180.0,
                      color: Colors.white10,
                      child: const Center(
                        child: CircularProgressIndicator(
                          strokeWidth: 2.0,
                          valueColor: AlwaysStoppedAnimation<Color>(Colors.white70),
                        ),
                      ),
                    );
                  },
                  errorBuilder: (context, error, stackTrace) {
                    return Container(
                      width: 240.0,
                      height: 180.0,
                      color: Colors.white10,
                      child: const Icon(
                        Icons.image_not_supported_rounded,
                        color: Colors.white54,
                      ),
                    );
                  },
                ),
                // Overlay ពេលវេលាពីលើរូបភាពនៅជ្រុងខាងស្តាំខាងក្រោម
                Positioned(
                  bottom: 6.0,
                  right: 8.0,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6.0, vertical: 2.0),
                    decoration: BoxDecoration(
                      color: Colors.black.withOpacity(0.5),
                      borderRadius: BorderRadius.circular(8.0),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          message.time,
                          style: const TextStyle(color: Colors.white, fontSize: 9.0),
                        ),
                        if (message.isSent) ...[
                          const SizedBox(width: 3.0),
                          Icon(
                            Icons.done_all_rounded,
                            size: 12.0,
                            color: message.isRead ? Colors.lightBlueAccent : Colors.white70,
                          ),
                        ]
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      );
    }

    // ៣. សារជាអត្ថបទធម្មតា (Text Message)
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          message.text,
          style: textStyle,
        ),
        const SizedBox(height: 4.0),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          mainAxisSize: MainAxisSize.min,
          children: [
            const SizedBox(width: 24.0), // បង្កើតគម្លាតពីអត្ថបទសារ
            Text(
              message.time,
              style: timeStyle,
            ),
            if (message.isSent) ...[
              const SizedBox(width: 4.0),
              Icon(
                Icons.done_all_rounded,
                size: 14.0,
                color: message.isRead ? Colors.lightBlueAccent : Colors.white60,
              ),
            ]
          ],
        ),
      ],
    );
  }
}

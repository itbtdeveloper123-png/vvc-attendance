# Poll Management Feature - Implementation Summary

## Overview
This document summarizes the implementation of the Poll Management feature for the VVC Attendance system. This feature allows administrators to create and manage employee voting polls, and enables employees to vote through the mobile app.

## Database Changes

### Modified Tables
The existing `poll_events` table has been enhanced with new columns:

- `access_code` (VARCHAR(50)): Optional access code for viewing poll results
- `excluded_employee_ids` (TEXT): JSON array of employee IDs who are not allowed to vote

### Table Structure
- **poll_events**: Main poll configuration table
  - Stores poll title, quarter, location, dates, access controls
  - Manages allowed and excluded employee lists
  
- **poll_candidates**: Candidates for each poll
  - Links employees to polls as candidates
  - Stores category information (Head Office, Store 318, Warehouse PSP, Warehouse PRV)
  
- **poll_votes**: Vote records
  - One vote per employee per poll (enforced by unique constraint)
  - Tracks who voted for which candidate

## Admin Panel Changes

### New Menu Item
- Added "គ្រប់គ្រងការបោះឆ្នោត" (Poll Management) to the admin sidebar
- Menu icon: `fa-solid fa-square-poll-vertical`

### New Pages
1. **Manage Polls** (`?page=polls&action=manage_polls`)
   - List all polls with status indicators
   - Create, edit, and delete polls
   - View poll details (quarter, location, dates)

2. **Create Poll** (`?page=polls&action=create_poll`)
   - Form to create new polls
   - Redirects to manage polls page

3. **Poll Results** (`?page=polls&action=poll_results`)
   - View voting results with percentages
   - Visual progress bars for each candidate
   - Filter by poll

### Poll Form Fields
- **Title** (required): Poll title
- **Quarter**: Q1, Q2, Q3, Q4 selection
- **Location/Warehouse**: Head Office, Store 318, Warehouse PSP, Warehouse PRV
- **Start Date** (required): When voting begins
- **End Date** (required): When voting ends
- **Access Code** (optional): Code required to view results
- **Excluded Employees** (optional): Employees not allowed to vote
- **Allowed Employees**: Employees permitted to vote (toggle selection)
- **Status**: Active/Inactive toggle

## API Endpoints

### Admin Endpoints
- `GET api.php?action=get_polls`: List all polls
- `GET api.php?action=get_poll&id={id}`: Get single poll details
- `POST api.php?action=save_poll`: Create or update poll
- `POST api.php?action=delete_poll&id={id}`: Delete poll
- `GET api.php?action=get_poll_results`: Get all poll results
- `GET api.php?action=get_employees`: Get active employees list
- `GET api.php?action=get_poll_with_access&id={id}&access_code={code}`: View poll with access code

### Mobile App Endpoints
- `GET api.php?action=get_active_polls`: Get active polls for current user
- `POST api.php?action=cast_vote`: Cast vote for a candidate

## Mobile App Changes

### New Screen
- **PollVotingScreen**: Employee voting interface
  - Lists active polls for the current user
  - Shows poll details (title, quarter, location, dates)
  - Displays candidates with vote buttons
  - Prevents duplicate voting
  - Shows voting status

### Integration
- Added "បោះឆ្នោតបុគ្គិក" (Employee Voting) to home screen quick actions
- Icon: `Icons.how_to_vote_rounded`
- Color: Green (#10B981)

## Features

### For Administrators
1. Create polls with specific timeframes
2. Target specific employee groups
3. Exclude certain employees from voting
4. Set optional access codes for result viewing
5. Monitor poll participation
6. View real-time results with percentages

### For Employees
1. View active polls they're eligible to vote in
2. See poll details (quarter, location, duration)
3. Vote for one candidate per poll
4. See voting status (already voted/pending)
5. Cannot vote multiple times in same poll

## Access Control

### Location-Based Access
The system supports location-based polling for:
- ការិយាល័យកណ្តាល (Head Office)
- ហាងទំនិញ ៣១៨ (Store 318)
- ឃ្លាំង PSP (Warehouse PSP)
- ឃ្លាំង PRV (Warehouse PRV)

### Employee Filtering
- **Allowed Employees**: Only selected employees can vote
- **Excluded Employees**: Specific employees blocked from voting
- **Empty Selection**: All active employees can vote (default)

## Usage Instructions

### Creating a Poll (Admin)
1. Navigate to "គ្រប់គ្រងការបោះឆ្នោត" in admin panel
2. Click "បង្កើតការបោះឆ្នោតថ្មី"
3. Fill in required fields:
   - Title (e.g., "បុគ្គលិកល្អប្រចាំត្រីមាសទី ១")
   - Quarter (e.g., Q1)
   - Location (e.g., Head Office)
   - Start and End dates
4. Optionally:
   - Set access code for result viewing
   - Select excluded employees
   - Choose allowed employees
5. Set status to "សកម្ម" (Active)
6. Click "រក្សាទុក" (Save)

### Adding Candidates
Currently, candidates need to be added directly to the database through the `poll_candidates` table. Future enhancement may include a UI for candidate management.

### Viewing Results (Admin)
1. Navigate to "លទ្ធផលការបោះឆ្នោត"
2. View all polls with voting results
3. See percentages and vote counts per candidate

### Voting (Mobile App)
1. Open mobile app
2. Tap "បោះឆ្នោតបុគ្គលិក" from home screen
3. View list of active polls
4. Tap "បោះឆ្នោត" next to desired candidate
5. Confirm vote
6. See voting status update

## Security Considerations

1. **One Vote Per Person**: Enforced at database level with unique constraint
2. **Time-Based Access**: Polls only active within specified date range
3. **Employee Filtering**: Only allowed employees can vote
4. **Access Control**: Admin permissions required for poll management
5. **Optional Privacy**: Access codes for sensitive poll results

## Future Enhancements

Potential improvements for future versions:
1. Candidate management UI in admin panel
2. Poll categories and types
3. Anonymous voting option
4. Export results to CSV/PDF
5. Poll notifications and reminders
6. Historical poll archive
7. Advanced filtering and search
8. Multi-language support for poll interface

## Troubleshooting

### Poll Not Showing for Employee
- Check poll is active (is_active = 1)
- Verify current date is within start/end dates
- Ensure employee is in allowed list (if specified)
- Confirm employee is not in excluded list
- Check employee employment status is "Active"

### Cannot Vote
- Verify employee hasn't already voted
- Check poll is still within date range
- Ensure candidate exists and belongs to poll
- Confirm employee has voting permissions

### Results Not Displaying
- Check if access code is required
- Verify correct access code is provided
- Ensure poll has candidates added
- Check that votes have been cast

## Files Modified

### Backend
- `admin_db_setup.php`: Database schema updates
- `admin_attendance.php`: Admin panel UI and menu
- `api.php`: API endpoints for poll operations

### Mobile App
- `lib/screens/home_screen.dart`: Added poll voting quick action
- `lib/screens/poll_voting_screen.dart`: New voting screen

## Database Migration

The database changes are handled automatically by the migration logic in `admin_db_setup.php`. The system will:
1. Add new columns to existing tables
2. Update unique constraints if needed
3. Maintain backward compatibility

No manual database intervention is required.

## Support

For issues or questions about the Poll Management feature:
1. Check this documentation first
2. Review error messages in browser console or app logs
3. Verify database schema is up to date
4. Check API responses in network tab
5. Ensure proper admin permissions are set
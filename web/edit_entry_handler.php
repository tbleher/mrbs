<?php
// $Id$

require_once "defaultincludes.inc";
require_once "mrbs_sql.inc";
require_once "functions_ical.inc";

// NOTE:  the code on this page assumes that array form variables are passed
// as an array of values, rather than an array indexed by value.   This is
// particularly important for checkbox arrays whicgh should be formed like this:
//
//    <input type="checkbox" name="foo[]" value="n">
//    <input type="checkbox" name="foo[]" value="m">
//
// and not like this:
//
//    <input type="checkbox" name="foo[n]" value="1">
//    <input type="checkbox" name="foo[m]" value="1">


// This page can be called with an Ajax call.  In this case it just checks
// the validity of a proposed booking and does not make the booking.

// Get non-standard form variables
$formvars = array('create_by'         => 'string',
                  'name'              => 'string',
                  'description'       => 'string',
                  'start_seconds'     => 'int',
                  'start_day'         => 'int',
                  'start_month'       => 'int',
                  'start_year'        => 'int',
                  'end_seconds'       => 'int',
                  'end_day'           => 'int',
                  'end_month'         => 'int',
                  'end_year'          => 'int',
                  'all_day'           => 'string',  // bool, actually
                  'type'              => 'string',
                  'rooms'             => 'array',
                  'original_room_id'  => 'int',
                  'ical_uid'          => 'string',
                  'ical_sequence'     => 'int',
                  'ical_recur_id'     => 'string',
                  'returl'            => 'string',
                  'id'                => 'int',
                  'rep_id'            => 'int',
                  'edit_type'         => 'string',
                  'rep_type'          => 'int',
                  'rep_end_day'       => 'int',
                  'rep_end_month'     => 'int',
                  'rep_end_year'      => 'int',
                  'rep_id'            => 'int',
                  'rep_day'           => 'array',   // array of bools
                  'rep_num_weeks'     => 'int',
                  'skip'              => 'string',  // bool, actually
                  'private'           => 'string',  // bool, actually
                  'confirmed'         => 'string',
                  'back_button'       => 'string',
                  'timetohighlight'   => 'int',
                  'page'              => 'string',
                  'commit'            => 'string',
                  'ajax'              => 'int');
                 
foreach($formvars as $var => $var_type)
{
  $$var = get_form_var($var, $var_type);
}

$skip_specials = array();
foreach( $special_events as $evtype => $values ) {
  if( !$values['allow-skip'] )
    $skip_specials[$evtype] = false;
  else
    $skip_specials[$evtype] = get_form_var("skip_$evtype", 'string');
}

// BACK:  we didn't really want to be here - send them to the returl
if (!empty($back_button))
{
  if (empty($returl))
  {
    $returl = "index.php";
  }
  header("Location: $returl");
  exit();
}

// Get custom form variables
$custom_fields = array();

// Get the information about the fields in the entry table
$fields = sql_field_info($tbl_entry);
          
foreach($fields as $field)
{
  if (!in_array($field['name'], $standard_fields['entry']))
  {
    switch($field['nature'])
    {
      case 'character':
        $f_type = 'string';
        break;
      case 'integer':
        $f_type = 'int';
        break;
      // We can only really deal with the types above at the moment
      default:
        $f_type = 'string';
        break;
    }
    $var = VAR_PREFIX . $field['name'];
    $custom_fields[$field['name']] = get_form_var($var, $f_type);
    if (($f_type == 'int') && ($custom_fields[$field['name']] === ''))
    {
      unset($custom_fields[$field['name']]);
    }
  }
}


// If this is an Ajax request and we're being asked to commit the booking, then
// we'll only have been supplied with parameters that need to be changed.  Fill in
// the rest from the existing boking information.
// Note: we assume that 
// (1) this is not a series (we can't cope with them yet)
// (2) we always get passed start_seconds and end_seconds in the Ajax data
if ($ajax && $commit)
{
  $old_booking = mrbsGetBookingInfo($id, $series);
  foreach ($formvars as $var => $var_type)
  {
    if (!isset($$var) || (($var_type == 'array') && empty($$var)))
    {
      switch ($var)
      {
        case 'rooms':
          $rooms = array($old_booking['room_id']);
          break;
        case 'original_room_id':
          $$var = $old_booking['room_id'];
          break;
        case 'private':
          $$var = $old_booking['status'] & STATUS_PRIVATE;
          break;
        case 'confirmed':
          $$var = !($old_booking['status'] & STATUS_TENTATIVE);
          break;
        case 'start_seconds';
          $date = getdate($old_booking['start_time']);
          $start_year = $date['year'];
          $start_month = $date['mon'];
          $start_day = $date['mday'];
          $start_seconds = $old_booking['start_time'] - mktime(0, 0, 0, $start_month, $start_day, $start_year);
          break;
        case 'end_seconds';
          $date = getdate($old_booking['end_time']);
          $end_year = $date['year'];
          $end_month = $date['mon'];
          $end_day = $date['mday'];
          $end_seconds = $old_booking['end_time'] - mktime(0, 0, 0, $end_month, $end_day, $end_year);
          break;
        default:
          $$var = $old_booking[$var];
          break;
      }
    }
  }

  // Now the custom fields
  $custom_fields = array();
  foreach ($fields as $field)
  {
    if (!in_array($field['name'], $standard_fields['entry']))
    {
      $custom_fields[$field['name']] = $old_booking[$field['name']];
    }
  }
}

if (!$ajax || !$commit)
{
  // Get the start day/month/year and make them the current day/month/year
  $day = $start_day;
  $month = $start_month;
  $year = $start_year;
}

// The id must be either an integer or NULL, so that subsequent code that tests whether
// isset($id) works.  (I suppose one could use !empty instead, but there's always the
// possibility that sites have allowed 0 in their auto-increment/serial columns.)
if (isset($id) && ($id == ''))
{
  unset($id);
}

// Truncate the name field to the maximum length as a precaution.
// Although the MAXLENGTH attribute is used in the <input> tag, this can
// sometimes be ignored by the browser, for example by Firefox when 
// autocompletion is used.  The user could also edit the HTML and remove
// the MAXLENGTH attribute.    Passing an oversize string to some
// databases (eg some versions of PostgreSQL) results in an SQL error,
// rather than silent truncation of the string.
$name = substr($name, 0, $maxlength['entry.name']);

// Make sure the area corresponds to the room that is being booked
if (!empty($rooms[0]))
{
  $area = get_area($rooms[0]);
  get_area_settings($area);  // Update the area settings
}
// and that $room is in $area
if (get_area($room) != $area)
{
  $room = get_default_room($area);
}


// Set up the return URL.    As the user has tried to book a particular room and a particular
// day, we must consider these to be the new "sticky room" and "sticky day", so modify the 
// return URL accordingly.

// First get the return URL basename, having stripped off the old query string
//   (1) It's possible that $returl could be empty, for example if edit_entry.php had been called
//       direct, perhaps if the user has it set as a bookmark
//   (2) Avoid an endless loop.   It shouldn't happen, but just in case ...
//   (3) If you've come from search, you probably don't want to go back there (and if you did we'd
//       have to preserve the search parameter in the query string)
$returl_base   = explode('?', basename($returl));
if (empty($returl) || ($returl_base[0] == "edit_entry.php") || ($returl_base[0] == "edit_entry_handler.php")
                   || ($returl_base[0] == "search.php"))
{
  switch ($default_view)
  {
    case "month":
      $returl = "month.php";
      break;
    case "week":
      $returl = "week.php";
      break;
    default:
      $returl = "day.php";
  }
}
else
{
  $returl = $returl_base[0];
}

// If we haven't been given a sensible date then get out of here and don't try and make a booking
if (!isset($day) || !isset($month) || !isset($year) || !checkdate($month, $day, $year))
{
  header("Location: $returl");
  exit;
}

// Now construct the new query string
$returl .= "?year=$year&month=$month&day=$day";

// If the old sticky room is one of the rooms requested for booking, then don't change the sticky room.
// Otherwise change the sticky room to be one of the new rooms.
if (!in_array($room, $rooms))
{
  $room = $rooms[0];
} 
// Find the corresponding area
$area = mrbsGetRoomArea($room);
// Complete the query string
$returl .= "&area=$area&room=$room";

// Handle private booking
// Enforce config file settings if needed
if ($private_mandatory) 
{
  $isprivate = $private_default;
}
else
{
  $isprivate = ($private) ? TRUE : FALSE;
}

// Check the user is authorised for this page
checkAuthorised();

// Also need to know whether they have admin rights
$user = getUserName();
$is_admin = (authGetUserLevel($user) >= 2);

// If they're not an admin and multi-day bookings are not allowed, then
// set the end date to the start date
if (!$is_admin && $auth['only_admin_can_book_multiday'])
{
  $end_day = $day;
  $end_month = $month;
  $end_year = $year;
}

// Check to see whether this is a repeat booking and if so, whether the user
// is allowed to make/edit repeat bookings.   (The edit_entry form should
// prevent you ever getting here, but this check is here as a safeguard in 
// case someone has spoofed the HTML)
if (isset($rep_type) && ($rep_type != REP_NONE) &&
    !$is_admin &&
    !empty($auth['only_admin_can_book_repeat']))
{
  showAccessDenied($day, $month, $year, $area, isset($room) ? $room : "");
  exit;
}

// Check that the user has permission to create/edit an entry for this room.
// Get the id of the room that we are creating/editing
if (isset($id))
{
  // Editing an existing booking: get the room_id from the database (you can't
  // get it from $rooms because they are the new rooms)
  $target_room = sql_query1("SELECT room_id FROM $tbl_entry WHERE id=$id LIMIT 1");
  if ($target_room < 0)
  {
    trigger_error(sql_error(), E_USER_WARNING);
    fatal_error(FALSE, get_vocab("fatal_db_error"));
  }
}
else
{
  // New booking: get the room_id from the form
  if (!isset($rooms[0]))
  {
    // $rooms[0] should always be set, because you can only get here
    // from edit_entry.php, where it will be set.   If it's not set
    // then something's gone wrong - probably somebody trying to call
    // edit_entry_handler.php directly from the browser - so get out 
    // of here and go somewhere safe.
    header("Location: index.php");
    exit;
  }
  $target_room = $rooms[0];
}
if (!getWritable($create_by, $user, $target_room))
{
  showAccessDenied($day, $month, $year, $area, isset($room) ? $room : "");
  exit;
}

// Form validation checks.   Normally checked for client side.
// Don't bother with them if this is an Ajax request.
if (!$ajax)
{
  if ($name == '')
  {
    print_header($day, $month, $year, $area, isset($room) ? $room : "");
  ?>
         <h1><?php echo get_vocab('invalid_booking'); ?></h1>
         <p>
           <?php echo get_vocab('must_set_description'); ?>
         </p>
  <?php
    // Print footer and exit
    print_footer(TRUE);
  }       


  if (($rep_type == REP_N_WEEKLY) && ($rep_num_weeks < 2))
  {
    print_header($day, $month, $year, $area, isset($room) ? $room : "");
  ?>
         <h1><?php echo get_vocab('invalid_booking'); ?></h1>
         <p>
           <?php echo get_vocab('you_have_not_entered')." ".get_vocab("useful_n-weekly_value"); ?>
         </p>
  <?php
    // Print footer and exit
    print_footer(TRUE);
  }

  if (count($is_mandatory_field))
  {
    foreach ($is_mandatory_field as $field => $value)
    {
      $field = preg_replace('/^entry\./', '', $field);
      if ($value && ($custom_fields[$field] == ''))
      {
        print_header($day, $month, $year, $area, isset($room) ? $room : "");
        ?>
        <h1><?php echo get_vocab('invalid_booking'); ?></h1>
        <p>
          <?php echo get_vocab('missing_mandatory_field')." \"".
                     get_loc_field_name($tbl_entry, $field)."\""; ?>
        </p>
        <?php
        // Print footer and exit
        print_footer(TRUE);
      }
    }
  }        
}

if ($enable_periods)
{
  $resolution = 60;
}

// When All Day is checked, $start_seconds and $end_seconds are disabled and so won't
// get passed through by the form.   We therefore need to set them.
if (!empty($all_day))
{
  if ($enable_periods)
  {
    $start_seconds = 12 * 60 * 60;
    // This is actually the start of the last period, which is what the form would
    // have returned.   It will get corrected in a moment.
    $end_seconds = $start_seconds + ((count($periods) - 1) * 60);
  }
  else
  {
    $start_seconds = (($morningstarts * 60) + $morningstarts_minutes) * 60;
    $end_seconds = (($eveningends * 60) + $eveningends_minutes) *60;
    $end_seconds += $resolution;  // We want the end of the last slot, not the beginning
  }
}

// Now work out the start and times
$starttime = mktime(intval($start_seconds/3600), intval(($start_seconds%3600)/60), 0,
                    $start_month, $start_day, $start_year);
$endtime   = mktime(intval($end_seconds/3600), intval(($end_seconds%3600)/60), 0,
                    $end_month, $end_day, $end_year);

// If we're using periods then the endtime we've been returned by the form is actually
// the beginning of the last period in the booking (it's more intuitive for users this way)
// so we need to add on 60 seconds (1 period)
if ($enable_periods)
{
  $endtime = $endtime + 60;
}

// Round down the starttime and round up the endtime to the nearest slot boundaries
// (This step is probably unnecesary now that MRBS always returns times aligned
// on slot boundaries, but is left in for good measure).                  
$am7 = mktime($morningstarts, $morningstarts_minutes, 0,
              $month, $day, $year, is_dst($month, $day, $year, $morningstarts));
$starttime = round_t_down($starttime, $resolution, $am7);
$endtime = round_t_up($endtime, $resolution, $am7);

// If they asked for 0 minutes, and even after the rounding the slot length is still
// 0 minutes, push that up to 1 resolution unit.
if ($endtime == $starttime)
{
  $endtime += $resolution;
}

// Now get the duration, which will be needed for email notifications
// (We do this before we adjust for DST so that the user sees what they expect to see)
$duration = $endtime - $starttime;
$duration_seconds = $endtime - $starttime;  // Preserve the duration in seconds - we need it later
$date = getdate($starttime);
if ($enable_periods)
{
  $period = (($date['hours'] - 12) * 60) + $date['minutes'];
  toPeriodString($period, $duration, $dur_units, FALSE);
}
else
{
  toTimeString($duration, $dur_units, FALSE);
}
  
// Adjust the endtime for DST
$endtime += cross_dst( $starttime, $endtime );


if (isset($rep_type) && ($rep_type != REP_NONE) &&
    isset($rep_end_month) && isset($rep_end_day) && isset($rep_end_year))
{
  // Get the repeat entry settings
  $end_date = mktime(intval($start_seconds/3600), intval(($start_seconds%3600)/60), 0,
                     $rep_end_month, $rep_end_day, $rep_end_year);
}
else
{
  $rep_type = REP_NONE;
  $end_date = 0;  // to avoid an undefined variable notice
}

if (!isset($rep_day))
{
  $rep_day = array();
}

$rep_opt = "";

// Processing for weekly and n-weekly repeats
if (isset($rep_type) && (($rep_type == REP_WEEKLY) || ($rep_type == REP_N_WEEKLY)))
{
  // If no repeat day has been set, then set a default repeat day
  // as the day of the week of the start of the period
  if (count($rep_day) == 0)
  {
    $rep_day[] = date('w', $starttime);
  }
  
  // Build string of weekdays to repeat on:
  for ($i = 0; $i < 7; $i++)
  {
    $rep_opt .= in_array($i, $rep_day) ? "1" : "0";  // $rep_opt is a string
  }
  
  // Make sure that the starttime and endtime coincide with a repeat day.  In
  // other words make sure that the first starttime and endtime define an actual
  // entry.   We need to do this because if we are going to construct an iCalendar
  // object, RFC 5545 demands that the start and end time are the first events of
  // a series.  ["The "DTSTART" property for a "VEVENT" specifies the inclusive
  // start of the event.  For recurring events, it also specifies the very first
  // instance in the recurrence set."]
  while (!$rep_opt[date('w', $starttime)])
  {
    $start = getdate($starttime);
    $end = getdate($endtime);
    $starttime = mktime($start['hours'], $start['minutes'], $start['seconds'],
                        $start['mon'], $start['mday'] + 1, $start['year']);
    $endtime = mktime($end['hours'], $end['minutes'], $end['seconds'],
                      $end['mon'], $end['mday'] + 1, $end['year']);
  }
}

// Expand a series into a list of start times:
if ($rep_type != REP_NONE)
{
  $reps = mrbsGetRepeatEntryList($starttime,
                                 isset($end_date) ? $end_date : 0,
                                 $rep_type, $rep_opt, $rep_num_weeks,
				 $max_rep_entrys);

  $special_event_list = get_special_events($start_year, $start_month, $start_day,
                                           $rep_end_year, $rep_end_month, $rep_end_day);
}

// When checking for overlaps, for Edit (not New), ignore this entry and series:
$repeat_id = 0;
if (isset($id))
{
  $ignore_id = $id;
  $repeat_id = sql_query1("SELECT repeat_id FROM $tbl_entry WHERE id=$id LIMIT 1");
  if ($repeat_id < 0)
  {
    $repeat_id = 0;
  }
}
else
{
  $ignore_id = 0;
}

// Acquire mutex to lock out others trying to book the same slot(s).
if (!sql_mutex_lock("$tbl_entry"))
{
  fatal_error(1, get_vocab("failed_to_acquire"));
}

// Validate the booking for (a) conflicting bookings and (b) conformance to rules
$valid_booking = TRUE;
$conflicts = array();     // Holds a list of all the conflicts
$skipped_bookings = array(); // Holds a list of all the bookings that were skipped for various reasons
$rules_broken = array();  // Holds an array of the rules that have been broken
$skip_lists = array();    // Holds a 2D array of bookings to skip past.  Indexed
                          // by room id and start time

foreach ( $rooms as $room_id )
{
  $skip_lists[$room_id] = array();
}

// filter out all repetitions that should be skipped because of holidays etc
if ($rep_type != REP_NONE && !empty($reps))
{
  $count = count($reps);
  for ($i = 0; $i < $count; $i++)
  {
    // calculate diff each time and correct where events
    // cross DST
    $diff = $duration_seconds;
    $diff += cross_dst($reps[$i], $reps[$i] + $diff);

    $skip_this = false;
    foreach ($special_event_list as $evtype => &$list) {
      if( !$skip_specials[$evtype] )
	continue;

      foreach($list as $h) {
	if (($h->getEnd() > $reps[$i]) && ($h->getStart() <= ($reps[$i]+$diff))) {
	  $start_string = utf8_strftime($strftime_format['date'], $h->getStart());
	  $end_string = utf8_strftime($strftime_format['date'], $h->getEnd()-1);
	  $time_string = $start_string === $end_string ? $start_string : $start_string . " - " . $end_string;
	  $skipped_bookings[] = '<b>' . $h->getProperty('summary') . "</b> ($time_string)";
	  foreach ( $rooms as $room_id )
	    $skip_lists[$room_id][] = $reps[$i];
	  $skip_this = true;
	}
      }

      if( $skip_this )
	break;
    }
    if( $skip_this )
      unset( $reps[$i] );
  }
}

// Check for any schedule conflicts in each room we're going to try and
// book in;  also check that the booking conforms to the policy
foreach ( $rooms as $room_id )
{
  if ($rep_type != REP_NONE && !empty($reps))
  {
    if(count($reps) < $max_rep_entrys)
    {
      foreach ($reps as $rep)
      {
        // calculate diff each time and correct where events
        // cross DST
        $diff = $duration_seconds;
        $diff += cross_dst($rep, $rep + $diff);

        $tmp = mrbsCheckFree($room_id,
                             $rep,
                             $rep + $diff,
                             $ignore_id,
                             $repeat_id);

        if (!empty($tmp))
        {
          // If we've been told to skip past existing bookings, then add
          // this start time to the list of start times to skip past.
          // Otherwise it's an invalid booking
          if ($skip)
          {
	    $skip_lists[$room_id][] = $rep;
	    $skipped_bookings = array_merge($skipped_bookings, $tmp);
          }
          else
          {
            $valid_booking = FALSE;
	    $conflicts = array_merge($conflicts, $tmp);
          }
        }
        // if we're not an admin for this room, check that the booking
        // conforms to the booking policy
        if (!auth_book_admin($user, $room_id))
        {
          $errors = mrbsCheckPolicy($rep, $duration_seconds);
          if (count($errors) > 0)
          {
            $valid_booking = FALSE;
            $rules_broken = array_merge($rules_broken, $errors);
          }
        }
      } // for
    }
    else
    {
      $valid_booking = FALSE;
      $rules_broken[] = get_vocab("too_may_entrys");
    }
  }
  else
  {
    $tmp = mrbsCheckFree($room_id, $starttime, $endtime-1, $ignore_id, 0);
    if (!empty($tmp))
      {
        $valid_booking = FALSE;
        $conflicts = array_merge($conflicts, $tmp);
      }
      // if we're not an admin for this room, check that the booking
      // conforms to the booking policy
      if (!auth_book_admin($user, $room_id))
      {
        $errors = mrbsCheckPolicy($starttime, $duration_seconds);
        if (count($errors) > 0)
        {
          $valid_booking = FALSE;
          $rules_broken = array_merge($rules_broken, $errors);
        }
      }
  }

} // end foreach rooms

// Tidy up the lists of conflicts and rules broken, getting rid of duplicates
$conflicts = array_values(array_unique($conflicts));
$skipped_bookings = array_values(array_unique($skipped_bookings));
$rules_broken = array_values(array_unique($rules_broken));
    
// If this is an Ajax request and if it's not a valid booking which we want
// to commit, then output the results and exit.   Otherwise we go on to commit the
// booking
if ($ajax && function_exists('json_encode'))
{
  if (!($commit && $valid_booking))
  {
    $result = array();
    $result['valid_booking'] = $valid_booking;
    $result['rules_broken'] = $rules_broken;
    $result['conflicts'] = $conflicts;
    $result['skipped_bookings'] = $skipped_bookings;
    echo json_encode($result);
    exit;
  }
}

// If the rooms were free, go ahead and process the bookings
if ($valid_booking)
{
  $new_details = array(); // We will pass this array in the Ajax result
  foreach ($rooms as $room_id)
  { 
    // Set the various bits in the status field as appropriate
    $status = 0;
    // Privacy status
    if ($isprivate)
    {
      $status |= STATUS_PRIVATE;  // Set the private bit
    }
    // If we are using booking approvals then we need to work out whether the
    // status of this booking is approved.   If the user is allowed to approve
    // bookings for this room, then the status will be approved, since they are
    // in effect immediately approving their own booking.  Otherwise the booking
    // will need to approved.
    if ($approval_enabled && !auth_book_admin($user, $room_id))
    {
      $status |= STATUS_AWAITING_APPROVAL;
    }
    // Confirmation status
    if ($confirmation_enabled && !$confirmed)
    {
      $status |= STATUS_TENTATIVE;
    }
    
    // Assemble the data in an array
    $data = array();
   
    // We need to work out whether this is the original booking being modified,
    // because, if it is, we keep the ical_uid and increment the ical_sequence.
    // We consider this to be the original booking if there was an original
    // booking in the first place (in which case the original room id will be set) and
    //      (a) this is the same room as the original booking
    //   or (b) there is only one room in the new set of bookings, in which case
    //          what has happened is that the booking has been changed to be in
    //          a new room
    //   or (c) the new set of rooms does not include the original room, in which
    //          case we will make the arbitrary assumption that the original booking
    //          has been moved to the first room in the list and the bookings in the
    //          other rooms are clones and will be treated as new bookings.
    
    if (isset($original_room_id) && 
        (($original_room_id == $room_id) ||
         (count($rooms) == 1) ||
         (($rooms[0] == $room_id) && !in_array($original_room_id, $rooms))))
    {
      // This is an existing booking which has been changed.   Keep the
      // original ical_uid and increment the sequence number.
      $data['ical_uid'] = $ical_uid;
      $data['ical_sequence'] = $ical_sequence + 1;
    }
    else
    {
      // This is a new booking.   We generate a new ical_uid and start
      // the sequence at 0.
      $data['ical_uid'] = generate_global_uid($name);
      $data['ical_sequence'] = 0;
    }
    $data['start_time'] = $starttime;
    $data['end_time'] = $endtime;
    $data['room_id'] = $room_id;
    $data['create_by'] = $create_by;
    $data['name'] = $name;
    $data['type'] = $type;
    $data['description'] = $description;
    $data['status'] = $status;
    foreach ($custom_fields as $key => $value)
    {
      $data[$key] = $value;
    }
    $data['rep_type'] = $rep_type;
    if ($rep_type != REP_NONE)
    {
      $data['end_date'] = $end_date;
      $data['rep_opt'] = $rep_opt;
      $data['rep_num_weeks'] = (isset($rep_num_weeks)) ? $rep_num_weeks : 0;
    }
    else
    {
      if ($repeat_id > 0)
      {
        // Mark changed entry in a series with entry_type:
        $data['entry_type'] = ENTRY_RPT_CHANGED;
        // Keep the same recurrence id (this never changes once an entry has been made)
        $data['ical_recur_id'] = $ical_recur_id;
      }
      else
      {
        $data['entry_type'] = ENTRY_SINGLE;
      }
      $data['entry_type'] = ($repeat_id > 0) ? ENTRY_RPT_CHANGED : ENTRY_SINGLE;
      $data['repeat_id'] = $repeat_id;
    }
    // Add in the list of bookings to skip
    if (!empty($skip_lists) && !empty($skip_lists[$room_id]))
    {
      $data['skip_list'] = $skip_lists[$room_id];
    }
    // The following elements are needed for email notifications
    $data['duration'] = $duration;
    $data['dur_units'] = $dur_units;

    if ($rep_type != REP_NONE)
    {
      $booking = mrbsCreateRepeatingEntrys($data);
      $new_id = $booking['id'];
      $is_repeat_table = $booking['series'];
    }
    else
    {
      // Create the entry:
      $new_id = mrbsCreateSingleEntry($data);
      $is_repeat_table = FALSE;
    }
    $new_details[] = array('id' => $new_id, 'room_id' => $room_id);
    $data['id'] = $new_id;  // Add in the id now we know it
    
    // Send an email if neccessary, provided that the entry creation was successful
    if ($need_to_send_mail && !empty($new_id))
    {
      // Only send an email if (a) this is a changed entry and we have to send emails
      // on change or (b) it's a new entry and we have to send emails for new entries
      if ((isset($id) && $mail_settings['on_change']) || 
          (!isset($id) && $mail_settings['on_new']))
      {
        require_once "functions_mail.inc";
        // Get room name and area name for email notifications.
        // Would be better to avoid a database access just for that.
        // Ran only if we need details
        if ($mail_settings['details'])
        {
          $sql = "SELECT R.room_name, A.area_name
                    FROM $tbl_room R, $tbl_area A
                   WHERE R.id=$room_id AND R.area_id = A.id
                   LIMIT 1";
          $res = sql_query($sql);
          $row = sql_row_keyed($res, 0);
          $data['room_name'] = $row['room_name'];
          $data['area_name'] = $row['area_name'];
        }
        // If this is a modified entry then get the previous entry data
        // so that we can highlight the changes
        if (isset($id))
        {
          if ($edit_type == "series")
          {
            $mail_previous = mrbsGetBookingInfo($repeat_id, TRUE);
          }
          else
          {
            $mail_previous = mrbsGetBookingInfo($id, FALSE);
          }
        }
        else
        {
          $mail_previous = array();
        }
        // Send the email
        $result = notifyAdminOnBooking($data, $mail_previous, !isset($id), $is_repeat_table);
      }
    }   
  } // end foreach $rooms

  // Delete the original entry
  if (isset($id))
  {
    mrbsDelEntry($user, $id, ($edit_type == "series"), 1);
  }

  sql_mutex_unlock("$tbl_entry");
  
  // Now it's all done.  Send the results if this was an Ajax booking
  // or else go back to the previous view
  if ($ajax)
  {
    require_once "functions_table.inc";
    $result = array();
    $result['valid_booking'] = $valid_booking;
    $result['new_details'] = $new_details;
    $result['slots'] = intval(($data['end_time'] - $data['start_time'])/$resolution);
    if ($page == 'day')
    {
      $result['table_innerhtml'] = day_table_innerhtml($day, $month, $year, $room, $area, $timetohighlight);
    }
    else
    {
      $result['table_innerhtml'] = week_table_innerhtml($day, $month, $year, $room, $area, $timetohighlight);
    }
    echo json_encode($result);
    exit;
  }
  else
  {
    header("Location: $returl");
    exit;
  }
}

// The room was not free.
sql_mutex_unlock("$tbl_entry");

if (!$valid_booking)
{
  print_header($day, $month, $year, $area, isset($room) ? $room : "");
    
  echo "<h2>" . get_vocab("sched_conflict") . "</h2>\n";
  if (!empty($rules_broken))
  {
    echo "<p>\n";
    echo get_vocab("rules_broken") . ":\n";
    echo "</p>\n";
    echo "<ul>\n";
    foreach ($rules_broken as $rule)
    {
      echo "<li>$rule</li>\n";
    }
    echo "</ul>\n";
  }
  if (!empty($conflicts))
  {
    echo "<p>\n";
    echo get_vocab("conflict").":\n";
    echo "</p>\n";
    echo "<ul>\n";
    foreach ($conflicts as $conflict)
    {
      echo "<li>$conflict</li>\n";
    }
    echo "</ul>\n";
  }
}

echo "<div id=\"submit_buttons\">\n";

// Back button
echo "<form method=\"post\" action=\"" . htmlspecialchars($returl) . "\">\n";
echo "<fieldset><legend></legend>\n";
echo "<input type=\"submit\" value=\"" . get_vocab("back") . "\">\n";
echo "</fieldset>\n";
echo "</form>\n";


// Skip and Book button (to book the entries that don't conflict)
// Only show this button if there were no policies broken and it's a series
if (empty($rules_broken)  &&
    isset($rep_type) && ($rep_type != REP_NONE))
{
  echo "<form method=\"post\" action=\"" . htmlspecialchars(basename($PHP_SELF)) . "\">\n";
  echo "<fieldset><legend></legend>\n";
  // Put the booking data in as hidden inputs
  $skip = 1;  // Force a skip next time round
  // First the ordinary fields
  foreach ($formvars as $var => $var_type)
  {
    if ($var_type == 'array')
    {
      // See the comment at the top of the page about array formats
      foreach ($$var as $value)
      {
        echo "<input type=\"hidden\" name=\"${var}[]\" value=\"" . htmlspecialchars($value) . "\">\n";
      }
    }
    else
    {
      echo "<input type=\"hidden\" name=\"$var\" value=\"" . htmlspecialchars($$var) . "\">\n";
    }
  }
  // Then the custom fields
  foreach($fields as $field)
  {
    if (array_key_exists($field['name'], $custom_fields))
    {
      echo "<input type=\"hidden\"" .
                  " name=\"" . VAR_PREFIX . $field['name'] . "\"" .
                  " value=\"" . htmlspecialchars($custom_fields[$field['name']]) . "\">\n";
    }
  }
  // Submit button
  echo "<input type=\"submit\"" .
              " value=\"" . get_vocab("skip_and_book") . "\"" .
              " title=\"" . get_vocab("skip_and_book_note") . "\">\n";
  echo "</fieldset>\n";
  echo "</form>\n";
}

echo "</div>\n";

require_once "trailer.inc";
?>

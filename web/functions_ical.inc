<?php

// $Id$

global $timezone;

// Get the VTIMEZONE component because we'll need it for creating events
// and the calendar
$vtimezone = get_vtimezone($timezone);


// Extracts a VTIMEZONE component from a VCALENDAR.
function extract_vtimezone($vcalendar)
{
  // The VTIMEZONE components are enclosed in a VCALENDAR, so we want to
  // extract the VTIMEZONE component.
  $vtimezone = strstr($vcalendar, "BEGIN:VTIMEZONE");
  // Would be simpler to use strstr() again, but the optional
  // third parameter was only introduced in PHP 5.3.0
  $pos = strpos($vtimezone, "END:VTIMEZONE");
  if ($pos !== FALSE)
  {
    $vtimezone = substr($vtimezone, 0, $pos);
    if (!empty($vtimezone))
    {
      $vtimezone .= "END:VTIMEZONE";
      return $vtimezone;
    }
  }
  return '';  // There wasn't a VTIMEZONE component
}


// download the contents of the web page at $url and return it as a string
function download($url)
{
  global $proxy;
  
  $connect_timeout  = 2;  // seconds
  $transfer_timeout = 2;  // seconds
  $curlopt_timeout  = 3;  // seconds
  
  // If we can we use cURL to download the page because it allows us to
  // set a timeout on establishing a connection as well as on the transfer time.
  // (We can only set a timeout on transfer time with file_get_contents()).  The
  // connection timeout is important because MRBS may be being used in sites
  // where direct access to the internet is not allowed.
  if (function_exists('curl_init'))
  {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $connect_timeout);
    curl_setopt($ch, CURLOPT_LOW_SPEED_TIME, $transfer_timeout);
    curl_setopt($ch, CURLOPT_TIMEOUT, $curlopt_timeout);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    $contents = curl_exec($ch);
    curl_close($ch);
  }
  
  // If there's no cURL then use file_get_contents()
  else
  {
    // Create the stream context so that we can (a) make sure the connection is closed,
    // because file_get_contents() does not return the contents when all the bytes
    // have been sent, but when the connection is closed and (b) set a timeout in case
    // the transfer is slow
    $context = stream_context_create(array('http' => array('header'=>'Connection: close',
                                                           'timeout' => $transfer_timeout)));
    // Suppress any timeout warnings
    $contents = @file_get_contents($url);
  }
  
  return $contents;
}


// Get a VTIMEZONE component for the timezone $tz.
// If none available returns FALSE.
//
// We cache the latest VTIMEZONE component in the database.  If it has expired
// we go to the web for the latest version or if there's nothing in the database
// in the first place we try and populate it from the VTIMEZONE definitions in
// the filesystem.
function get_vtimezone($tz)
{
  global $tbl_zoneinfo, $zoneinfo_update, $zoneinfo_expiry;
  
  $outlook_compatible = TRUE;    // We use the Outlook compatible versions
  $tz_dir = ($outlook_compatible) ? "tzurl/zoneinfo-outlook" : "tzurl/zoneinfo";  
  $tz_file = "$tz_dir/$tz.ics";  // A fallback for a VTIMEZONE definition
  
  $vtimezone = FALSE;  // Default value in case we don't find one
  
  // Convert booleans into 1 or 0 (necessary for the database)
  $outlook_compatible = ($outlook_compatible) ? 1 : 0;
  
  // Acquire a mutex to lock out others who might be accessing 
  // the table, to stop somebody inserting a record at the same
  // time as us (we want just one entry per timezone)
  if (!sql_mutex_lock("$tbl_zoneinfo"))
  {
    fatal_error(TRUE, get_vocab("failed_to_acquire"));
  }
  
  // Look and see if there's a component in the database
  $sql = "SELECT vtimezone, last_updated
            FROM $tbl_zoneinfo
           WHERE timezone='" . addslashes($tz) . "'
             AND outlook_compatible=$outlook_compatible
           LIMIT 1";
  $res = sql_query($sql);
  if ($res === FALSE)
  {
    trigger_error(sql_error(), E_USER_WARNING);
    fatal_error(FALSE, get_vocab("fatal_db_error"));
  }
  elseif (sql_count($res) > 0)
  {
    // If there's something in the database and it hasn't expired, then
    // that's it.
    $row = sql_row_keyed($res, 0);
    $vtimezone = $row['vtimezone'];
    if ($zoneinfo_update && ((time() - $row['last_updated']) >= $zoneinfo_expiry))
    {
      // Otherwise, provided that the config variable $zoneinfo_update
      // is true, we get the URL of the latest version on the web,
      // and update the database.
      //
      // (Note that a VTIMEZONE component can contain a TZURL property which
      // gives the URL of the most up to date version.  Calendar applications
      // should be able to check this themselves, but we might as well give them
      // the most up to date version in the first place).
      $properties = explode("\r\n", ical_unfold($vtimezone));
      foreach ($properties as $property)
      {
        if (strpos($property, "TZURL:") === 0)
        {
          $tz_url = substr($property, 6);  // 6 is the length of "TZURL:"
        }
      }
      
      $vcalendar = download($tz_url);
      
      if ($vcalendar)
      {
        $new_vtimezone = extract_vtimezone($vcalendar);
        if (!empty($new_vtimezone))
        {
          // We've got a valid VTIMEZONE, so we can overwrite $vtimezone
          $vtimezone = $new_vtimezone;
          // Update the database
          $sql = "UPDATE $tbl_zoneinfo
                     SET vtimezone='" . addslashes($vtimezone) . "',
                         last_updated=" . time() . "
                   WHERE timezone='" . addslashes($tz) . "'
                     AND outlook_compatible=$outlook_compatible";
          if (sql_command($sql) < 0)
          {
            trigger_error(sql_error(), E_USER_WARNING);
            fatal_error(FALSE, get_vocab("fatal_db_error"));
          }
        }
      }
    }
  }
  // There's nothing in the database, so try and get a VTIMEZONE component
  // from the filesystem.
  else
  {
    $vcalendar = file_get_contents($tz_file);
    
    if ($vcalendar)
    {
      $vtimezone = extract_vtimezone($vcalendar);
      if (!empty($vtimezone))
      {
        $sql = "INSERT INTO $tbl_zoneinfo
                (timezone, outlook_compatible, vtimezone, last_updated)
                VALUES ('" . addslashes($tz) . "', 
                        $outlook_compatible,
                        '" . addslashes($vtimezone) . "', " .
                        time() . ")";
        if (sql_command($sql) < 0)
        {
          trigger_error(sql_error(), E_USER_WARNING);
          fatal_error(FALSE, get_vocab("fatal_db_error"));
        }
      }
    }
  }
  // Tidy up and return
  sql_mutex_unlock("$tbl_zoneinfo");  // Release the mutex
  return $vtimezone;
}


// "Folds" lines longer than 75 octets.  Multi-byte safe.
//
// "Lines of text SHOULD NOT be longer than 75 octets, excluding the line
// break.  Long content lines SHOULD be split into a multiple line
// representations using a line "folding" technique.  That is, a long
// line can be split between any two characters by inserting a CRLF
// immediately followed by a single linear white-space character (i.e.,
// SPACE or HTAB).  Any sequence of CRLF followed immediately by a
// single linear white-space character is ignored (i.e., removed) when
// processing the content type."  (RFC 5545)
function ical_fold($str)
{ 
  $line_split = "\r\n ";  // The RFC also allows a tab instead of a space
  $space_octets = utf8_bytecount(' ');  // Could be two bytes if we're using UTF-16
  $octets_max = 75;
  
  $result = '';
  $octets = 0;
  $byte_index = 0;
  
  while (isset($byte_index))
  {
    // Get the next character
    $prev_byte_index = $byte_index;
    $char = utf8_seq($str, $byte_index);

    $char_octets = $byte_index - $prev_byte_index;
    // If it's a CR then look ahead to the following character, if there is one
    if (($char == "\r") && isset($byte_index))
    {
      $this_byte_index = $byte_index;
      $next_char = utf8_seq($str, $byte_index);
      // If that's a LF then take the CR, and advance by one character
      if ($next_char == "\n")
      {
        $result .= $char;    // take the CR
        $char = $next_char;  // advance by one character
        $octets = 0;         // reset the octet counter to the beginning of the line
        $char_octets = 0;    // and pretend the LF is zero octets long so that after
                             // we've added it in we're still at the beginning of the line
      }
      // otherwise stay where we were
      else
      {
        $byte_index = $this_byte_index;
      }
    }
    // otherwise if this character will take us over the octet limit for the line,
    // fold the line and set the octet count to however many octets a space takes
    // (the folding involves adding a CRLF followed by one character, a space or a tab)
    //
    // [Note:  It's not entirely clear from the RFC whether the octet that is introduced
    // when folding counts towards the 75 octets.   Some implementations (eg Google
    // Calendar as of Jan 2011) do not count it.   However it can do no harm to err on
    // the safe side and include the initial whitespace in the count.]
    elseif (($octets + $char_octets) > $octets_max)
    {
      $result .= $line_split;
      $octets = $space_octets;
    }
    // finally add the character to the result string and up the octet count
    $result .= $char;
    $octets += $char_octets;
  }
  return $result;
}


// Reverse the RFC 5545 folding process, which splits lines into groups
// of max 75 octets separated by 'CRLFspace' or 'CRLFtab'
function ical_unfold($str)
{
  // Deal with the trivial cases
  if (!isset($str))
  {
    return NULL;
  }
  if ($str == '')
  {
    return $str;
  }
  
  // We've got a non-zero length string
  $result = '';
  $byte_index = 0;
  
  while (isset($byte_index))
  {
    // Get the next character
    $char = utf8_seq($str, $byte_index);
    // If it's a CR then look ahead to the following character, if there is one
    if (($char == "\r") && isset($byte_index))
    {
      $char = utf8_seq($str, $byte_index);
      // If that's a LF then look ahead to the next character, if there is one
      if (($char == "\n") && isset($byte_index))
      {
        $char = utf8_seq($str, $byte_index);
        // If that's a space or a tab then ignore it because we've just had a fold
        // sequence.    Otherwise add the characters into the result string.
        if (($char != " ") && ($char != "\t"))
        {
          $result .= "\r\n" . $char;
        }
      }
      else
      {
        $result .= "\r" . $char;
      }
    }
    else
    {
      $result .= $char;
    }
  }
  
  return $result;
}


// Escape text for use in an iCalendar text value
function ical_escape_text($str)
{
  // Escape '\'
  $str = str_replace("\\", "\\\\", $str);
  // Escape ';'
  $str = str_replace(";", "\;", $str);
  // Escape ','
  $str = str_replace(",", "\,", $str);
  // EOL can only be \n
  $str = str_replace("\r\n", "\n", $str);
  // Escape '\n'
  $str = str_replace("\n", "\\n", $str);
  return $str;
}

// Escape text for use in an iCalendar quoted string
function ical_escape_quoted_string($str)
{
  // From RFC 5545:
  //    quoted-string = DQUOTE *QSAFE-CHAR DQUOTE

  //    QSAFE-CHAR    = WSP / %x21 / %x23-7E / NON-US-ASCII
  //    ; Any character except CONTROL and DQUOTE
  
  // We'll just get rid of any double quotes, replacing them with a space.
  // (There is no way of escaping double quotes)
  $str = str_replace('"', ' ', $str);
  return $str;
}


// Create an iCalendar Recurrence Rule
function create_rrule($data)
{
  // Create an array which can be used to map day of the week numbers (0..6)
  // onto days of the week as defined in RFC 5545
  $RFC_5545_days = array('SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA');
  $rule = '';
  if (!isset($data['rep_type']))
  {
    return $rule;
  }
  switch($data['rep_type'])
  {
    case REP_NONE:
      return $rule;
      break;
    case REP_DAILY:
      $rule .= "FREQ=DAILY";
      break;
    case REP_WEEKLY:
    case REP_N_WEEKLY;
      $rule .= "FREQ=WEEKLY";
      // Interval for N_WEEKLY (Interval defaults to 1)
      if ($data['rep_type'] == REP_N_WEEKLY)
      {
        $rule .= ";INTERVAL=" . $data['rep_num_weeks'];
      }
      // Get the repeat days of the week
      $days_of_week = array();
      for ($i = 0; $i < 7; $i++)
      {
        if ($data['rep_opt'][$i])
        {
          $days_of_week[] = $RFC_5545_days[$i];
        }
      }
      $dow_list = implode(',', $days_of_week);
      if (!empty($dow_list))
      {
        $rule .= ";BYDAY=$dow_list";
      }
      break;
    case REP_MONTHLY_SAMEDAY:
      $dow = date('w', $data['start_time']);  // day of the week
      $dom = date('j', $data['start_time']);  // day of the month
      // Work out the week of the month.    If this is the fifth week of the month
      // then make it -1 (last week of the month in RFC 5545 terms)
      $wom = intval($dom/7) + 1;
      if ($wom > 4)
      {
        $wom = -1;
      }
      $wom = sprintf('%+d', $wom);
      $rule .= ";BYDAY=";
      $rule .= $wom;
      $rule .= $RFC_5545_days[$dow];
    case REP_MONTHLY:
      $rule .= "FREQ=MONTHLY";
      break;
    case REP_YEARLY:
      $rule .= "FREQ=YEARLY";
      break;
  }
  // The UNTIL date-time "MUST be specified in UTC time"
  $rule .= ";UNTIL=" . gmdate(RFC5545_FORMAT . '\Z', $data['end_date']);

  return $rule;
}


// Create a comma separated list of dates for use with the EXDATE property.
// The TZID parameter if used must be added separately
function create_exdate_list($dates)
{
  global $vtimezone, $timezone;
  
  $results = array();
  
  foreach ($dates as $date)
  {
    if ($vtimezone === FALSE)
    {
      $results[] = gmdate(RFC5545_FORMAT . '\Z', $date);
    }
    else
    {
      $results[] = date(RFC5545_FORMAT, $date);
    }
  }
  return implode(',', $results);
}


// Create an RFC 5545 iCalendar Event component
function create_ical_event($method, $data, $text_description, $html_description, $addresses, $series=FALSE)
{
  require_once "functions_mail.inc";
  
  global $confirmation_enabled, $mail_settings, $timezone, $vtimezone;
  
  $use_html = $mail_settings['html'] && !empty($html_description);
  
  $results = array();

  $results[] = "BEGIN:VEVENT";
  $results[] = "UID:" . $data['ical_uid'];  // compulsory
  $results[] = "DTSTAMP:" . gmdate(RFC5545_FORMAT . '\Z');  // compulsory
  if (!empty($data['last_updated']))
  {
    $results[] = "LAST-MODIFIED:" . gmdate(RFC5545_FORMAT . '\Z', $data['last_updated']);
  }

  // Note: we try and write the event times in the format of a local time with
  // a timezone reference (ie RFC 5545 Form #3).   Only if we can't do that do we
  // fall back to a UTC time (ie RFC 5545 Form #2).
  //
  // The reason for this is that although this is not required by RFC 5545 (see
  // Appendix A.2), its predecessor, RFC 2445, did require it for recurring
  // wvents and is the standard against which older applications, notably Exchange
  // 2007, are written.   Note also that when using a local timezone format the
  // VTIMEZONE component must be provided (this is done in create_icalendar() ).  Some
  // applications will work without the VTIMEZONE component, but many follow the
  // standard and do require it.  Here is an extract from RFC 2445:
  
  // 'When used with a recurrence rule, the "DTSTART" and "DTEND" properties MUST be 
  // specified in local time and the appropriate set of "VTIMEZONE" calendar components
  // MUST be included.' 
  
  if ($vtimezone === FALSE)
  {
    $results[] = "DTSTART:" . gmdate(RFC5545_FORMAT . '\Z', $data['start_time']);
    $results[] = "DTEND:" . gmdate(RFC5545_FORMAT . '\Z', $data['end_time']);
  }
  else
  {
    $results[] = "DTSTART;TZID=$timezone:" . date(RFC5545_FORMAT, $data['start_time']);
    $results[] = "DTEND;TZID=$timezone:" . date(RFC5545_FORMAT, $data['end_time']);
  }
  
  if ($series)
  {
    $results[] = "RRULE:" . create_rrule($data);
    if (!empty($data['skip_list']))
    {
      $results[] = "EXDATE" . 
                   (($vtimezone === FALSE) ? ":" : ";TZID=$timezone:") .
                   create_exdate_list($data['skip_list']);
    }
  }
  $results[] = "SUMMARY:" . ical_escape_text($data['name']);
  // Put the HTML version in an ALTREP, just in case there are any Calendars out there
  // that support it (although at the time of writing, Dec 2010, none are known)
  $results[] = "DESCRIPTION" .
               ((($use_html && !empty($html_description['cid'])) ? ";ALTREP=\"CID:" . $html_description['cid'] . "\"" : "") . ":" .
               ical_escape_text($text_description['content']));
  // This is another way of getting an HTML description, used by Outlook.  However it 
  // seems to be very limited
  if ($use_html)
  {
    $results[] = "X-ALT-DESC;FMTTYPE=text/html:" . ical_escape_text($html_description['content']);
  }
  $results[] = "LOCATION:" . ical_escape_text($data['area_name'] . " - " . $data['room_name']);
  $results[] = "SEQUENCE:" . $data['ical_sequence'];
  // If this is an individual member of a series then set the recurrence id
  if (!$series && ($data['entry_type'] != ENTRY_SINGLE))
  {
    $results[] = "RECURRENCE-ID:" . $data['ical_recur_id'];
  }
  // STATUS:  As we can have confirmed and tentative bookings we will send that information
  // in the Status property, as some calendar apps will use it.   For example Outlook 2007 will
  // distinguish between tentative and confirmed bookings.  However, having sent it we need to
  // send a STATUS:CANCELLED on cancellation.    It's not clear to me from the spec whether this
  // is strictly necessary but it can do no harm and there are some apps that seem to need it -
  // for example Outlook 2003 (but not 2007).
  if ($method == "CANCEL")
  {
    $results[] = "STATUS:CANCELLED";
  }
  else
  {
    $results[] = "STATUS:" . (($data['status'] & STATUS_TENTATIVE) ? "TENTATIVE" : "CONFIRMED");
  }
  
  /*  
  Class is commented out for the moment.  To be useful it probably needs to go
  hand in hand with an ORGANIZER, otherwise people won't be able to see their own
  bookings
  // CLASS
  $results[] = "CLASS:" . (($data['status'] & STATUS_PRIVATE) ? "PRIVATE" : "PUBLIC");
  */
  
  // ORGANIZER
  // The organizer is the booking creator if we've got an email address for him/her.
  // Otherwise we'll make the 'from' address the organizer.   In both cases we'll try
  // and extract the common name from the email address.
  $organizer_email = get_email_address($data['create_by']);
  if (empty($organizer_email))
  {
    $organizer = parse_address($addresses['from']);
    if (empty($organizer['common_name']))
    {
      $organizer['common_name'] = $organizer['address'];
    }
  }
  else
  {
    $organizer = parse_address($organizer_email);
    if (empty($organizer['common_name']))
    {
      // If the email address doesn't have a common name
      // then we can use the creator's username
      $organizer['common_name'] = $data['create_by'];
    }
  }
  if (!empty($organizer['address']))
  {
    $results[] = "ORGANIZER;CN=\"" . ical_escape_quoted_string($organizer['common_name']) . "\":mailto:" . $organizer['address'];
  }
  
  // Put the people on the "to" list as required participants and those on the cc
  // list as non particpants.   In theory the email client can then decide whether
  // to enter the booking automaticaly on the user's calendar - although at the
  // time of writing (Dec 2010) there don't seem to be any that do so!
  if (!empty($addresses))
  {
    $attendees = $addresses;  // take a copy of $addresses as we're going to alter it
    $keys = array('to', 'cc');  // We won't do 'bcc' as they need to stay blind
    foreach ($keys as $key)
    {
      $attendees[$key] = explode(',', $attendees[$key]);  // convert the list into an array
    }
    foreach ($keys as $key)
    {
      foreach ($attendees[$key] as $attendee)
      {
        if (!empty($attendee))
        {
          switch ($key)
          {
            case 'to':
              $role = "REQ-PARTICIPANT";
              break;
            default:
              if (in_array($attendee, $attendees['to']))
              {
                // It's possible that an address could appear on more than one
                // line, in which case we only want to have one ATTENDEE property
                // for that address and we'll chose the REQ-PARTICIPANT.   (Apart
                // from two conflicting ATTENDEES not making sense, it also breaks
                // some applications, eg Apple Mail/iCal)
                continue 2;  // Move on to the next attendeee
              }
              $role = "NON-PARTICIPANT";
              break;
          }
          // Use the common name if there is one
          $attendee = parse_address($attendee);
          $results[] = "ATTENDEE;" .
                       ((!empty($attendee['common_name'])) ? "CN=\"" . ical_escape_quoted_string($attendee['common_name']) . "\";" : "") .
                       "PARTSTAT=NEEDS-ACTION;ROLE=$role:mailto:" . $attendee['address'];
        }
      }
    }
  }

  $results[] = "END:VEVENT";
  
  $result = implode(ICAL_EOL, $results);  // No CRLF at end: that will be added later
  
  return $result;
}


// Creates an iCalendar object in RFC 5545 format
//    $method      string   the RFC 5545 METHOD (eg "REQUEST", "PUBLISH", "CANCEL")
//    $components  array    an array of iCalendar components, each a string  
function create_icalendar($method, $components)
{
  require_once "version.inc";
  
  global $vtimezone;

  $results = array();
  $results[] = "BEGIN:VCALENDAR";
  // Compulsory properties
  $results[] = "PRODID:-//MRBS//NONSGML " . get_mrbs_version() . " //EN";
  $results[] = "VERSION:2.0";
  // Optional properties
  $results[] = "CALSCALE:GREGORIAN";
  $results[] = "METHOD:$method";
  
  // Add in the VTIMEZONE component if there is one (see the comment in
  // create_ical_event() above)
  if ($vtimezone)
  {
    $results[] = $vtimezone;
  }
  
  // Add in each component
  foreach ($components as $component)
  {
    $results[] = $component;
  }

  $results[] = "END:VCALENDAR";
  
  $result = implode(ICAL_EOL, $results);
  $result .= ICAL_EOL;  // Has to end with a CRLF
  
  $result = ical_fold($result);

  return $result;
}


// outputs an iCalendar based on the data in $res, the result of an SQL query.
//
//    &$res       resource  the result of an SQL query on the entry table, which
//                          has been sorted by repeat_id, ical_recur_id (both ascending).
//                          As well as all the fields in the entry table, the rows will 
//                          also contain the area name, the room name and the repeat
//                          details (rep_type, end_date, rep_opt, rep_num_weeks)
//    $export_end int       a Unix timestamp giving the end limit for the export
function export_icalendar(&$res, $keep_private, $export_end=PHP_INT_MAX)
{
  require_once "functions_view.inc";
  require_once "mrbs_sql.inc";
  
  // We construct an iCalendar by going through the rows from the SQL query.  Because
  // it was sorted by repeat_id and then by ical_recur_id we will
  //    - get all the individual entries (which will have repeat_id 0)
  //    - then get the series.    For each series we have to:
  //        - identify the series information.   This is the original series information
  //          so we can only get it from an entry that has not been changed, ie has 
  //          entry_type == ENTRY_RPT_ORIGINAL.   If there isn't one of these then it
  //          does not matter, because every entry will have been changed and so there
  //          is no need for the original data. [Note: another way of getting the
  //          series information would have been to get it as part of the query]
  //        - identify any events that have been changed from the standard, ie events
  //          with entry_type == ENTRY_RPT_CHANGED
  //        - identify any events from the original series that have been cancelled.  We
  //          can do this because we know from the repeat information the events that
  //          should be there and we can tell from the recurrence-id the events that
  //          are actually there.   We can then issue cancellations for the missing
  //          events.
  
  // Initialize an array to hold the events and a variable to keep track
  // of the last repeat id we've seen
  $ical_events = array();
  $last_repeat_id = 0;
  $private_text = "[" . get_vocab("private") . "]";
  
  for ($i = 0; ($row = sql_row_keyed($res, $i)); $i++)
  {
    $text_body = array();
    $html_body = array();
    // If this is an individual entry, then construct an event
    if ($row['repeat_id'] == 0)
    {
      $text_body['content'] = create_details_body($row, FALSE, $keep_private);
      $html_body['content'] = "<table>" . create_details_body($row, TRUE, $keep_private) . " </table>";
      $ical_events[] = create_ical_event("REQUEST", $row, $text_body, $html_body, NULL, FALSE);
    }
    // Otherwise it's a series
    else
    {
      // if it's a series that we haven't seen yet, then construct an event
      if ($row['repeat_id'] != $last_repeat_id)
      {
        // Unless is the very first series, check to see whether we got
        // all the entries we would have expected in the last series and
        // issue cancellations for those that are missing
        if (isset($actual_entries))
        {
          $missing_entries = array_diff($expected_entries, $actual_entries);
          foreach ($missing_entries as $missing_entry)
          {
            if ($keep_private)
            {
              // We don't want private details appearing in the .ics file
              $start_row['name'] = $private_text;
              $start_row['create_by'] = $private_text;
            }
            $duration = $start_row['end_time'] - $start_row['start_time'];
            $start_row['start_time'] = $missing_entry;
            $start_row['end_time'] = $start_row['start_time'] + $duration;
            $start_row['ical_recur_id'] = gmdate(RFC5545_FORMAT . '\Z', $missing_entry);
            $ical_events[] = create_ical_event("CANCEL", $start_row, NULL, NULL, NULL, FALSE);
          }
        }
        // Initialise for the new series
        $last_repeat_id = $row['repeat_id'];
        unset($replace_index);
        // We need to set the repeat start and end dates because we've only been
        // asked to export dates in the report range.  The end date will be the earlier
        // of the series end date and the report end date.  The start date of the series
        // will be the recurrence-id of the first entry in the series, which is this one
        // thanks to the SQL query which ordered the entries by recurrence-id.
        $start_row = $row;  // Make a copy of the data because we are going to tweak it.
        $start_row['end_date'] = min($export_end, $start_row['end_date']);
        $duration = $start_row['end_time'] - $start_row['start_time'];
        $start_row['start_time'] = strtotime($row['ical_recur_id']);
        $start_row['end_time'] = $start_row['start_time'] + $duration;
        // However, if this is a series member that has been changed, then we 
        // cannot trust the rest of the data (eg the description).   We will
        // use this data for now in case we don't get anything better, but we
        // will make a note that we really need an unchanged member of the series, 
        // which will have the correct data for the series which we can use to
        // replace this event.   (Of course, if we don't get an unchanged member
        // then it doesn't matter because all the original members will have been
        // changed and so there's no longer any need for the original data.)
        if ($row['entry_type'] == ENTRY_RPT_CHANGED)
        {
          // Record the index number of the event that needs to be replaced.
          // As we have not yet added that event to the array, it will be
          // the current length of the array.
          $replace_index = count($ical_events);
        }
        // Construct an array of the entries we'd expect to see in this series so that
        // we can check whether any are missing and if so set their status to cancelled.
        // (We use PHP_INT_MAX rather than $max_rep_entrys because $max_rep_entrys may
        // have changed since the series was created.)
        $expected_entries = mrbsGetRepeatEntryList($start_row['start_time'], 
                                                   $start_row['end_date'],
                                                   $start_row['rep_type'],
                                                   $start_row['rep_opt'],
                                                   $start_row['rep_num_weeks'],
                                                   PHP_INT_MAX);
        // And keep an array of all the entries we actually see
        $actual_entries = array();
        // Create the series event
        $text_body['content'] = create_details_body($start_row, FALSE, $keep_private);
        $html_body['content'] = "<table>" . create_details_body($start_row, TRUE, $keep_private) . "</table>";
        $ical_events[] = create_ical_event("REQUEST", $start_row, $text_body, $html_body, NULL, TRUE);
      }
      // Add this entry to the array of ones we've seen
      $actual_entries[] = strtotime($row['ical_recur_id']);
      // And if it's a series member that has been altered
      if ($row['entry_type'] == ENTRY_RPT_CHANGED)
      {
        $text_body['content'] = create_details_body($row, FALSE, $keep_private);
        $html_body['content'] = "<table>" . create_details_body($row, TRUE, $keep_private) . "</table>";
        $ical_events[] = create_ical_event("REQUEST", $row, $text_body, $html_body, NULL, FALSE);
      }
      // Otherwise it must be an original member, in which case check
      // to see if we were looking out for one
      elseif (isset($replace_index))
      {
        // Use this row to define the sequence as it has got all the original
        // data, except that we need to change the start and end times, keeping
        // the original duration.   We get the start time from the recurrence
        // id of the first member of the series, which we saved earlier on.
        $duration = $row['end_time'] - $row['start_time'];
        $row['start_time'] = $start_row['start_time'];
        $row['end_time'] = $row['start_time'] + $duration;
        $row['end_date'] = min($export_end, $row['end_date']);
        $text_body['content'] = create_details_body($row, FALSE, $keep_private);
        $html_body['content'] = "<table>" . create_details_body($row, TRUE, $keep_private) . "</table>";
        $ical_events[$replace_index] = create_ical_event("REQUEST", $row, $text_body, $html_body, NULL, TRUE);
        // Clear the $replace_index now that we've found an original entry
        unset ($replace_index);
      }
    }
  }
  
  // We've got to the end of the rows, so check to see whether there were
  // any entries missing from the very last series, if there was one, and
  // issue cancellations for the missing entries
  if (isset($actual_entries))
  {
    $missing_entries = array_diff($expected_entries, $actual_entries);
    foreach ($missing_entries as $missing_entry)
    {
      if ($keep_private)
      {
        // We don't want private details appearing in the .ics file
        $start_row['name'] = $private_text;
        $start_row['create_by'] = $private_text;
      }
      $duration = $start_row['end_time'] - $start_row['start_time'];
      $start_row['start_time'] = $missing_entry;
      $start_row['end_time'] = $start_row['start_time'] + $duration;
      $start_row['ical_recur_id'] = gmdate(RFC5545_FORMAT . '\Z', $missing_entry);
      $ical_events[] = create_ical_event("CANCEL", $start_row, NULL, NULL, NULL, FALSE);
    }
  }
  // Build the iCalendar from the array of events and output it
  $icalendar = create_icalendar("REQUEST", $ical_events);
  echo $icalendar;
}

function ical_to_event_list($file, $start_time, $end_time)
{
  $hd = array();
  if (file_exists($file)) {
    require_once "SG_iCalendar.inc";
    $ical = new SG_iCal($file);

    foreach($ical->getEvents() as $id => $hev) {
      if ( ($hev->getStart()<=$end_time && $hev->getEnd()>=$start_time) )
	$hd[] = $hev;
    }
  }
  return $hd;
}

/**
 * Returns all special events (eg holidays and vacations) in the given range (inclusive).
 */
function get_special_events($start_year, $start_month, $start_day, $end_year, $end_month, $end_day)
{
  global $special_events;

  $start = mktime(0, 0, 0, $start_month, $start_day, $start_year);
  $end = mktime(23, 59, 59, $end_month, $end_day, $end_year);

  $ret = array();
  foreach( $special_events as $type => $values ) {
    $ret[$type] = array();
    for( $year = $start_year; $year <= $end_year; ++$year ) {
      if (isset($values['files'][$year])) {
	$list = ical_to_event_list($values['files'][$year], $start, $end);
	$ret[$type] = array_merge($ret[$type], $list);
      }
    }
  }
  return $ret;
}

?>

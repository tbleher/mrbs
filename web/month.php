<?php
// $Id$

// mrbs/month.php - Month-at-a-time view

require_once "defaultincludes.inc";
require_once "mincals.inc";
require_once "functions_table.inc";
require_once "functions_ical.inc";

$debug_flag = get_form_var('debug_flag', 'int');

// 3-value compare: Returns result of compare as "< " "= " or "> ".
function cmp3($a, $b)
{
  if ($a < $b)
  {
    return "< ";
  }
  if ($a == $b)
  {
    return "= ";
  }
  return "> ";
}

// Check the user is authorised for this page
checkAuthorised();

$user = getUserName();

// print the page header
print_header($day, $month, $year, $area, isset($room) ? $room : "");


// Note $room will be 0 if there are no rooms; this is checked for below.

// Month view start time. This ignores morningstarts/eveningends because it
// doesn't make sense to not show all entries for the day, and it messes
// things up when entries cross midnight.
$month_start = mktime(0, 0, 0, $month, 1, $year);

// What column the month starts in: 0 means $weekstarts weekday.
$weekday_start = (date("w", $month_start) - $weekstarts + 7) % 7;

$days_in_month = date("t", $month_start);

$month_end = mktime(23, 59, 59, $month, $days_in_month, $year);

if ( $enable_periods )
{
  $resolution = 60;
  $morningstarts = 12;
  $eveningends = 12;
  $eveningends_minutes = count($periods)-1;
}


// Define the start and end of each day of the month in a way which is not
// affected by daylight saving...
for ($j = 1; $j<=$days_in_month; $j++)
{
  // are we entering or leaving daylight saving
  // dst_change:
  // -1 => no change
  //  0 => entering DST
  //  1 => leaving DST
  $dst_change[$j] = is_dst($month,$j,$year);
  if (empty( $enable_periods ))
  {
    $midnight[$j]=mktime(0,0,0,$month,$j,$year, is_dst($month,$j,$year, 0));
    $midnight_tonight[$j]=mktime(23,59,59,$month,$j,$year, is_dst($month,$j,$year, 23));
  }
  else
  {
    $midnight[$j]=mktime(12,0,0,$month,$j,$year, is_dst($month,$j,$year, 0));
    $midnight_tonight[$j]=mktime(12,count($periods),59,$month,$j,$year, is_dst($month,$j,$year, 23));
  }
}

// Section with areas, rooms, minicals.
?>
<div class="screenonly">
  <div id="dwm_header">
<?php

// Get the area and room names (we will need them later for the heading)
$this_area_name = "";
$this_room_name = "";
$this_area_name = sql_query1("SELECT area_name FROM $tbl_area WHERE id=$area AND disabled=0 LIMIT 1");
$this_room_name = sql_query1("SELECT room_name FROM $tbl_room WHERE id=$room AND disabled=0 LIMIT 1");
// The room is invalid if it doesn't exist, or else it has been disabled, either explicitly
// or implicitly because the area has been disabled
$room_invalid = ($this_area_name === -1) || ($this_room_name === -1);
                          
// Show all available areas
echo make_area_select_html('month.php', $area, $year, $month, $day);  
// Show all available rooms in the current area:
echo make_room_select_html('month.php', $area, $room_selected ? $room : "", $year, $month, $day);
    
// Draw the three month calendars
minicals($year, $month, $day, $area, $room_selected ? $room : "", 'month');
echo "</div>\n";

// End of "screenonly" div
echo "</div>\n";

// Don't continue if this room is invalid, which could be because the area
// has no rooms, or else the room or area has been disabled
if ($room_invalid)
{
  echo "<h1>".get_vocab("no_rooms_for_area")."</h1>";
  require_once "trailer.inc";
  exit;
}

// Show Month, Year, Area, Room header:
$this_page_title = $room_selected ? "$this_area_name - $this_room_name" : $this_area_name;
echo "<div id=\"dwm\">\n";
echo "<h2>" . utf8_strftime($strftime_format['monthyear'], $month_start)
  . " - " . htmlspecialchars($this_page_title) . "</h2>\n";
echo "</div>\n";

// Show Go to month before and after links
//y? are year and month and day of the previous month.
//t? are year and month and day of the next month.
//c? are year and month of this month.   But $cd is the day that was passed to us.

$i= mktime(12,0,0,$month-1,1,$year);
$yy = date("Y",$i);
$ym = date("n",$i);
$yd = $day;
while (!checkdate($ym, $yd, $yy) && ($yd > 1))
{
  $yd--;
}

$i= mktime(12,0,0,$month+1,1,$year);
$ty = date("Y",$i);
$tm = date("n",$i);
$td = $day;
while (!checkdate($tm, $td, $ty) && ($td > 1))
{
  $td--;
}

$cy = date("Y");
$cm = date("m");
$cd = $day;    // preserve the day information
while (!checkdate($cm, $cd, $cy) && ($cd > 1))
{
  $cd--;
}


$room_link = $room_selected ? "&amp;room=$room" : "";
$before_after_links_html = "<div class=\"screenonly\">
  <div class=\"date_nav\">
    <div class=\"date_before\">
      <a href=\"month.php?year=$yy&amp;month=$ym&amp;day=$yd&amp;area=$area$room_link\">
          &lt;&lt;&nbsp;".get_vocab("monthbefore")."
        </a>
    </div>
    <div class=\"date_now\">
      <a href=\"month.php?year=$cy&amp;month=$cm&amp;day=$cd&amp;area=$area$room_link\">
          ".get_vocab("gotothismonth")."
        </a>
    </div>
    <div class=\"date_after\">
       <a href=\"month.php?year=$ty&amp;month=$tm&amp;day=$td&amp;area=$area$room_link\">
          ".get_vocab("monthafter")."&nbsp;&gt;&gt;
        </a>
    </div>
  </div>
</div>
";

print $before_after_links_html;

if ($debug_flag)
{
  echo "<p>DEBUG: month=$month year=$year start=$weekday_start range=$month_start:$month_end</p>\n";
}

// Used below: localized "all day" text but with non-breaking spaces:
$all_day = preg_replace("/ /", "&nbsp;", get_vocab("all_day"));

$special_event_list = get_special_events($year, $month, 1, $year, $month, $days_in_month);

//Get all meetings for this month in the room that we care about
// row[0] = Start time
// row[1] = End time
// row[2] = Entry ID
// This data will be retrieved day-by-day fo the whole month
for ($day_num = 1; $day_num<=$days_in_month; $day_num++)
{
  if( $room_selected ) {
    $sql = "SELECT start_time, end_time, id, name, type,
                   repeat_id, status, create_by, \"dummy\" AS room_name
              FROM $tbl_entry
             WHERE room_id=$room
               AND start_time <= $midnight_tonight[$day_num] AND end_time > $midnight[$day_num]
          ORDER BY start_time";
  } else {
    $sql = "SELECT start_time, end_time, $tbl_entry.id AS id, name, type,
                   repeat_id, status, create_by, room_name
              FROM $tbl_entry, $tbl_room
             WHERE $tbl_room.area_id = $area AND $tbl_entry.room_id = $tbl_room.id
               AND start_time <= $midnight_tonight[$day_num] AND end_time > $midnight[$day_num]
          ORDER BY start_time, end_time, name, type, status, repeat_id, room_name";
  }
  // Build an array of information about each day in the month.
  // The information is stored as:
  //  d[monthday]["id"][] = ID of each entry, for linking.
  //  d[monthday]["data"][] = "start-stop" times or "name" of each entry.

  $res = sql_query($sql);
  if (! $res)
  {
    trigger_error(sql_error(), E_USER_WARNING);
    fatal_error(TRUE, get_vocab("fatal_db_error"));
  }
  else
  {
    for ($i = 0; ($row = sql_row_keyed($res, $i)); $i++)
    {
      if ($debug_flag)
      {
        echo "<br>DEBUG: result $i, id ".$row['id'].", starts ".$row['start_time'].", ends ".$row['end_time']."\n";
      }

      if ($debug_flag)
      {
        echo "<br>DEBUG: Entry ".$row['id']." day $day_num\n";
      }
      $d[$day_num]["id"][] = $row['id'];
      $d[$day_num]["color"][] = $row['type'];
      $d[$day_num]["is_repeat"][] = !empty($row['repeat_id']);
      
      // Handle private events
      if (is_private_event($row['status'] & STATUS_PRIVATE)) 
      {
        if (getWritable($row['create_by'], $user, $room)) 
        {
          $private = FALSE;
        }
        else 
        {
          $private = TRUE;
        }
      }
      else 
      {
        $private = FALSE;
      }

      if ($private & $is_private_field['entry.name']) 
      {
        $d[$day_num]["status"][] = $row['status'] | STATUS_PRIVATE;  // Set the private bit
        $d[$day_num]["shortdescrip"][] = '['.get_vocab('unavailable').']';
      }
      else
      {
        $d[$day_num]["status"][] = $row['status'] & ~STATUS_PRIVATE;  // Clear the private bit
        $d[$day_num]["shortdescrip"][] = htmlspecialchars($row['name']);
      }

      $d[$day_num]["room"][] = htmlspecialchars($row['room_name']);
      

      // Describe the start and end time, accounting for "all day"
      // and for entries starting before/ending after today.
      // There are 9 cases, for start time < = or > midnight this morning,
      // and end time < = or > midnight tonight.
      // Use ~ (not -) to separate the start and stop times, because MSIE
      // will incorrectly line break after a -.
     
      #$la = '⇦';
      #$ra = '⇨';
      #$la = '←';
      #$ra = '→';
      #$la = '⇐';
      #$ra = '⇒';
      $la = '&lt;=';
      $ra = '=&gt;';
 
      if (empty( $enable_periods ) )
      {
        switch (cmp3($row['start_time'], $midnight[$day_num]) . cmp3($row['end_time'], $midnight_tonight[$day_num] + 1))
        {
          case "> < ":         // Starts after midnight, ends before midnight
          case "= < ":         // Starts at midnight, ends before midnight
            $d[$day_num]["data"][] = htmlspecialchars(utf8_strftime(hour_min_format(), $row['start_time'])) . "~" . htmlspecialchars(utf8_strftime(hour_min_format(), $row['end_time']));
            break;
          case "> = ":         // Starts after midnight, ends at midnight
            $d[$day_num]["data"][] = htmlspecialchars(utf8_strftime(hour_min_format(), $row['start_time'])) . "~24:00";
            break;
          case "> > ":         // Starts after midnight, continues tomorrow
            $d[$day_num]["data"][] = htmlspecialchars(utf8_strftime(hour_min_format(), $row['start_time'])) . "~$ra";
            break;
          case "= = ":         // Starts at midnight, ends at midnight
            $d[$day_num]["data"][] = $all_day;
            break;
          case "= > ":         // Starts at midnight, continues tomorrow
            $d[$day_num]["data"][] = $all_day . $ra;
            break;
          case "< < ":         // Starts before today, ends before midnight
            $d[$day_num]["data"][] = "$la~" . htmlspecialchars(utf8_strftime(hour_min_format(), $row['end_time']));
            break;
          case "< = ":         // Starts before today, ends at midnight
            $d[$day_num]["data"][] = $la . $all_day;
            break;
          case "< > ":         // Starts before today, continues tomorrow
            $d[$day_num]["data"][] = $la . $all_day . $ra;
            break;
        }
      }
      else
      {
        $start_str = period_time_string($row['start_time']);
        $end_str   = period_time_string($row['end_time'], -1);
        switch (cmp3($row['start_time'], $midnight[$day_num]) . cmp3($row['end_time'], $midnight_tonight[$day_num] + 1))
        {
          case "> < ":         // Starts after midnight, ends before midnight
          case "= < ":         // Starts at midnight, ends before midnight
            $d[$day_num]["data"][] = $start_str . "~" . $end_str;
            break;
          case "> = ":         // Starts after midnight, ends at midnight
            $d[$day_num]["data"][] = $start_str . "~24:00";
            break;
          case "> > ":         // Starts after midnight, continues tomorrow
            $d[$day_num]["data"][] = $start_str . "~$ra";
            break;
          case "= = ":         // Starts at midnight, ends at midnight
            $d[$day_num]["data"][] = $all_day;
            break;
          case "= > ":         // Starts at midnight, continues tomorrow
            $d[$day_num]["data"][] = $all_day . $ra;
            break;
          case "< < ":         // Starts before today, ends before midnight
            $d[$day_num]["data"][] = $la . $end_str;
            break;
          case "< = ":         // Starts before today, ends at midnight
            $d[$day_num]["data"][] = $la . $all_day;
            break;
          case "< > ":         // Starts before today, continues tomorrow
            $d[$day_num]["data"][] = $la . $all_day . $ra;
            break;
        }
      }
    }
  }
}
if ($debug_flag)
{
  echo "<p>DEBUG: Array of month day data:</p><pre>\n";
  for ($i = 1; $i <= $days_in_month; $i++)
  {
    if (isset($d[$i]["id"]))
    {
      $n = count($d[$i]["id"]);
      echo "Day $i has $n entries:\n";
      for ($j = 0; $j < $n; $j++)
      {
        echo "  ID: " . $d[$i]["id"][$j] .
          " Data: " . $d[$i]["data"][$j] . "\n";
      }
    }
  }
  echo "</pre>\n";
}

echo "<table class=\"dwm_main\" id=\"month_main\">\n";

// Weekday name header row:
echo "<thead>\n";
echo "<tr>\n";
for ($weekcol = 0; $weekcol < 7; $weekcol++)
{
  if (is_hidden_day(($weekcol + $weekstarts) % 7))
  {
    // These days are to be hidden in the display (as they are hidden, just give the
    // day of the week in the header row 
    echo "<th class=\"hidden_day\">" . day_name(($weekcol + $weekstarts)%7) . "</th>";
  }
  else
  {
    echo "<th>" . day_name(($weekcol + $weekstarts)%7) . "</th>";
  }
}
echo "\n</tr>\n";
echo "</thead>\n";

// Main body
echo "<tbody>\n";
echo "<tr>\n";

// Skip days in week before start of month:
for ($weekcol = 0; $weekcol < $weekday_start; $weekcol++)
{
  if (is_hidden_day(($weekcol + $weekstarts) % 7))
  {
    echo "<td class=\"hidden_day\"><div class=\"cell_container\">&nbsp;</div></td>\n";
  }
  else
  {
    echo "<td class=\"invalid\"><div class=\"cell_container\">&nbsp;</div></td>\n";
  }
}

// Draw the days of the month:
for ($cday = 1; $cday <= $days_in_month; $cday++)
{
  // if we're at the start of the week (and it's not the first week), start a new row
  if (($weekcol == 0) && ($cday > 1))
  {
    echo "</tr><tr>\n";
  }
  
  // output the day cell
  if (is_hidden_day(($weekcol + $weekstarts) % 7))
  {
    // These days are to be hidden in the display (as they are hidden, just give the
    // day of the week in the header row 
    echo "<td class=\"hidden_day\">\n";
    echo "<div class=\"cell_container\">\n";
    echo "<div class=\"cell_header\">\n";
    // first put in the day of the month
    echo "<span>$cday</span>\n";
    echo "</div>\n";
    echo "</div>\n";
    echo "</td>\n";
  }
  else
  {   
    echo "<td class='valid'>\n";
    echo "<div class='cell_container'>\n";
    
    $query_string = "edit_entry.php?area=$area$room_link&amp;year=$year&amp;month=$month&amp;day=$cday";
    if ($enable_periods)
    {
      $query_string .= "&amp;period=0";
    }
    else
    {
      $query_string .= "&amp;hour=$morningstarts&amp;minute=0";
    }
    
    $special_event_text = '';
    $special_event_count = 0;
    foreach ($special_event_list as $type => &$list) {
      $prefix = isset($special_events[$type]['prefix']) ? $special_events[$type]['prefix'] : '';
      $suffix = isset($special_events[$type]['suffix']) ? $special_events[$type]['suffix'] : '';
      $tooltip_prefix = isset($special_events[$type]['tooltip-prefix']) ? $special_events[$type]['tooltip-prefix'] : '';
      $tooltip_suffix = isset($special_events[$type]['tooltip-suffix']) ? $special_events[$type]['tooltip-suffix'] : '';
      foreach($list as $h) {
	if (($h->getEnd() > $midnight[$cday]) && ($h->getStart() <= $midnight_tonight[$cday])) {
	  $text = $prefix . htmlspecialchars($h->getProperty('summary')) . $suffix;
	  $tooltip = $tooltip_prefix . htmlspecialchars($h->getProperty('summary')) . $tooltip_suffix;
	  $text_nbsp = preg_replace(array("/ /", "/-/"), array("&nbsp;", "&#8209;"), $text);
	  $special_event_text .= "<div class='special_event special_event_pos$special_event_count'>";
	  $special_event_text .= "<a title=\"".$tooltip."\" href=\"$query_string\"";
	  $special_event_text .= " class='se-$type'>".$text_nbsp."</a></div>";
	  $special_event_count++;
	}
      }
    }

    echo "<div class='cell_header'";
    if( $special_event_count > 0 )
	echo " style='min-height: " . number_format($special_event_count*1.4, 1, '.', '')."em;'";
    echo ">\n";
    // first put in the day of the month
    echo "<a class='monthday' href='day.php?year=$year&amp;month=$month&amp;day=$cday&amp;area=$area'>$cday</a>\n";
    echo "</div>\n";
    echo $special_event_text;

    // then the link to make a new booking
    
    echo "<a class=\"new_booking\" href=\"$query_string\">\n";
    if ($show_plus_link)
    {
      echo "<img src=\"images/new.gif\" alt=\"New\" width=\"10\" height=\"10\">\n";
    }
    echo "</a>\n";
    
    // then any bookings for the day
    if (isset($d[$cday]["id"][0]))
    {
      echo "<div class=\"booking_list\">\n";
      $rooms = "";
      $n = count($d[$cday]["id"]);
      // Show the start/stop times, 1 or 2 per line, linked to view_entry.
      for ($i = 0; $i < $n; $i++)
      {
        if( !$room_selected ) {
          // if no room was selected by the user, show an area overview. For
          // this, all bookings that have the same short description and
          // start-/end-time are accumulated into one booking
          $booking_link = "view_entry.php?id=" . $d[$cday]["id"][$i] . "&amp;day=$cday&amp;month=$month&amp;year=$year";
          if( $rooms != "" )
            $rooms .= ", ";
          $rooms .= "<a href=\"$booking_link\" class=\"plainlink\">" . htmlspecialchars($d[$cday]["room"][$i]) . "</a>";

          if(    $i < $n-1
              && $d[$cday]["shortdescrip"][$i] === $d[$cday]["shortdescrip"][$i+1]
              && $d[$cday]["data"][$i] === $d[$cday]["data"][$i+1]
              && $d[$cday]["color"][$i] === $d[$cday]["color"][$i+1]  
              && $d[$cday]["status"][$i] === $d[$cday]["status"][$i+1] ) {
            // next room has same description as our, just accumulate parameters
            continue;
          }
        }

        // give the enclosing div the appropriate width: full width if both,
        // otherwise half-width (but use 49.9% to avoid rounding problems in some browsers)
        $class = $d[$cday]["color"][$i]; 
        if ($d[$cday]["status"][$i] & STATUS_PRIVATE)
        {
          $class .= " private";
        }
        if ($approval_enabled && ($d[$cday]["status"][$i] & STATUS_AWAITING_APPROVAL))
        {
          $class .= " awaiting_approval";
        }
        if ($confirmation_enabled && ($d[$cday]["status"][$i] & STATUS_TENTATIVE))
        {
          $class .= " tentative";
        }  
        echo "<div class=\"" . $class . "\"" .
          " style=\"width: " . (($monthly_view_entries_details == "both") ? '100%' : '49.9%') . "\">\n";
        $booking_link = "view_entry.php?id=" . $d[$cday]["id"][$i] . "&amp;day=$cday&amp;month=$month&amp;year=$year";
        $slot_text = $d[$cday]["data"][$i];
        $description_text = utf8_substr($d[$cday]["shortdescrip"][$i], 0, 255);
        $full_text = $slot_text . " " . $description_text;
        switch ($monthly_view_entries_details)
        {
          case "description":
          {
            $display_text = $description_text;
            break;
          }
          case "slot":
          {
            $display_text = $slot_text;
            break;
          }
          case "both":
          {
            $display_text = $full_text;
            break;
          }
          default:
          {
            echo "error: unknown parameter";
          }
        }
        if( $room_selected ) {
	  echo "<a href=\"$booking_link\" title=\"$full_text\">";
	} else {
	  echo "<div style='padding-left: 2px;'>";
	}
        echo ($d[$cday]['is_repeat'][$i]) ? "<img class=\"repeat_symbol\" src=\"images/repeat.png\" alt=\"" . get_vocab("series") . "\" title=\"" . get_vocab("series") . "\" width=\"10\" height=\"10\">" : '';
        if( $room_selected ) {
	  echo "$display_text</a>\n";
	} else {
	  echo "$display_text</div>\n";
	}

        if( !$room_selected ) {
          // output all rooms that belong to this booking
          echo "<div class=\"room_details\">(" . $rooms . ")</div>";
          $rooms = "";
        }
        echo "</div>\n";
      }
      echo "</div>\n";
    }
    
    echo "</div>\n";
    echo "</td>\n";
  }
  
  // increment the day of the week counter
  if (++$weekcol == 7)
  {
    $weekcol = 0;
  }

} // end of for loop going through valid days of the month

// Skip from end of month to end of week:
if ($weekcol > 0)
{
  for (; $weekcol < 7; $weekcol++)
  {
    if (is_hidden_day(($weekcol + $weekstarts) % 7))
    {
      echo "<td class=\"hidden_day\"><div class=\"cell_container\">&nbsp;</div></td>\n";
    }
    else
    {
      echo "<td class=\"invalid\"><div class=\"cell_container\">&nbsp;</div></td>\n";
    }
  }
}
echo "</tr></tbody></table>\n";

print $before_after_links_html;
show_colour_key();

require_once "trailer.inc";
?>

-- $Id$

-- Fixes a mistake in the previous upgrade.  If we've got an individual member of a
-- series that has been modified, ie has entry_type=2, then the sequence number 
-- cannot be 0.   We will set it to 1.

UPDATE %DB_TBL_PREFIX%entry 
SET ical_sequence=1 WHERE ical_sequence=0 AND entry_type=2;

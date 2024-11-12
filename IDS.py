import sys
import os
import random
import statistics
import numpy as np

# Basic command line parsing
if len(sys.argv) != 5:
    print("Usage: <function> <events_file> <stats_file> <days>")
    sys.exit(1)

function, events_file, stats_file, days = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
print(f"Running function: {function}, Events file: {events_file}, Stats file: {stats_file}, Days: {days}")

counter = 0 # counter to track the number of simulation event created

def parse_events(file_path):
    '''
    Parses an events configuration file and extracts information about each event.

    Args:
        file_path (str): The path to the events file. The file should contain the number of events on the 
                         first line, followed by lines for each event in the format:
                         Event name:[CD]:minimum:maximum:weight

    Returns:
        dict: A dictionary where each key is an event name, and each value is another dictionary with 
              details about the event, including:
              - 'type' (str): 'C' for continuous or 'D' for discrete.
              - 'min' (float or None): The minimum allowed value for the event (or None if unspecified).
              - 'max' (float or None): The maximum allowed value for the event (or None if unspecified).
              - 'weight' (int): A positive integer weight used in the alert engine.

    Notes:
        Continuous events ('C') allow decimal values, while discrete events ('D') only allow integer values.
    '''
    events = {} # a dictionary of dictionary to store the event information

    # open n read file
    with open(file_path, 'r') as f:
        event_count = int(f.readline().strip())

        # for each row in file
        for _ in range(event_count):
            # delimiter by ':'
            line = f.readline().strip().split(':')

            # data format {Logins : {'type': 'D', 'min': 0.0, 'max': None, 'weight': 2}}
            event_name, event_type, min_val, max_val, weight = line[0], line[1], line[2], line[3], line[4]

            if event_type == 'D':
                # store in event dictionary
                events[event_name] = {
                    'type': event_type,
                    'min': int(min_val) if min_val else int(0),
                    'max': int(max_val) if max_val else int(0),
                    'weight': int(weight)
                }
            else:
                # store in event dictionary
                events[event_name] = {
                    'type': event_type,
                    'min': float(min_val) if min_val else 0.0,
                    'max': float(max_val) if max_val else 0.0,
                    'weight': int(weight)
                }
            # print(f"File event: {event_name} -> {events[event_name]}")
            
        if events:  # This checks if events is not empty
            print(f"Successfully loaded {file_path} file")
        else:
            print(f"Failed to load {file_path} file, events is empty.")

    return events


def parse_stats(file_path):
    '''
    Parses a statistics configuration file and extracts statistical information for each event.

    Args:
        file_path (str): The path to the statistics file. The file should contain the number of events on the 
                         first line, followed by lines for each event in the format:
                         Event name:mean:standard deviation

    Returns:
        dict: A dictionary where each key is an event name, and each value is another dictionary with 
              details about the event's statistics, including:
              - 'mean' (float): The mean value for the event.
              - 'std_dev' (float): The standard deviation for the event.

    Notes:
        The statistics in this file will be used to compare against event data for intrusion detection.
    '''
    
    stats = {}  # a dictionary of dictionary to store the event information

    # open n read file
    with open(file_path, 'r') as f:
        event_count = int(f.readline().strip())
        
        # for each row in file
        for _ in range(event_count):
            # delimiter by ':'
            line = f.readline().strip().split(':')

            # data format {Logins : {'mean': 4.0, 'std_dev': 1.5}}
            event_name, mean, std_dev = line[0], float(line[1]), float(line[2])
            stats[event_name] = {
                'mean': float(mean),
                'std_dev': float(std_dev)
            }
            # print(f"File stats: {event_name} -> {stats[event_name]}")

        if stats:  # This checks if stats is not empty
            print(f"Successfully loaded {file_path} file")
        else:
            print(f"Failed to load {file_path} file, stats is empty.")

    return stats


def cal_threshold(basestats):
    '''
    Calculates a threshold value based on the weights of events in the basestats dictionary.

    Args:
        basestats (dict): A dictionary where each key is an event name, and each value is a dictionary 
                          containing event statistics, including a 'weight' field with a positive integer.

    Returns:
        int: The calculated threshold, which is twice the sum of all event weights in basestats.

    Notes:
        This threshold can be used to set an alert level for an intrusion detection system. 
        By doubling the sum of event weights, this threshold can help in identifying abnormal activity 
        based on the cumulative significance of event weights.
    '''

    threshold = 0 # thershold to be 2 * sum for weights
    
    # loop through basestats and sum the weights
    for event_name in basestats:
        threshold += basestats[event_name]['weight']

    threshold = threshold * 2 # sum * 2

    #print(f"threshold: {threshold}")
    return threshold


def cal_basestats(events, stats):
    '''
    Combines event statistics from the stats and events dictionaries,
    adds weight information from events, 
    calculate and add the threshold,
    and saves the result to a text file.
    Returns a dictionary with the combined base statistics.
    '''
    
    basestats = {}  # Dictionary to store combined statistics for each event
    
    # Combine stats and weights from events and stats dictionaries
    for event_name, stat_values in stats.items():
        if event_name in events:
            combined_entry = {
                'mean': stat_values['mean'],
                'std_dev': stat_values['std_dev'],
                'min': events[event_name]['min'],
                'max': events[event_name]['max'],
                'weight': events[event_name]['weight'],
                'type': events[event_name]['type'],
            }
            basestats[event_name] = combined_entry
            #print(f"Base stats: {event_name} -> {combined_entry}")
        else:
            print(f"Warning: {event_name} found in stats but not in events.")

    if basestats:  # This checks if basestats is not empty
        # calculate threshold 
        threshold = cal_threshold(basestats)
        
        # Save basestats to a text file in a tab-separated format
        with open("basestats.txt", 'w') as f:
            # Write header with alignment
            f.write(f"{'Event Name':<15}\t{'Mean':<8}\t{'Std Dev':<8}\t{'Min':<8}\t{'Max':<8}\t{'Weight':<8}\t{'Data Type':<8}\n")
            
            # Write each event's stats with better alignment
            for event_name, data in basestats.items():

                # Format continuous data to 2 decimal place
                if basestats[event_name]['type'] == 'C':
                    line = f"{event_name:<15}\t{data['mean']:<8}\t{data['std_dev']:<8}\t{data['min']:<8.2f}\t{data['max']:<8.2f}\t{data['weight']:<8}\t{data['type']:<8}\n"

                else:
                    line = f"{event_name:<15}\t{data['mean']:<8}\t{data['std_dev']:<8}\t{data['min']:<8}\t{data['max']:<8}\t{data['weight']:<8}\t{data['type']:<8}\n"

                f.write(line)

            # set threshold
            basestats['Threshold'] = threshold
            f.write(f"{'Threshold':<15}\t{threshold:<8}\n")

        print("Successfully save Basestats to basestats.txt")
    else:
        print(f"Basestats is empty.")

    return basestats


def validate_consistency(events, stats):
    '''
    Validates the consistency between the events and stats data.

    Args:
        events (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                       details about the event, including:
                       - 'type' (str): Event type ('C' for continuous, 'D' for discrete).
                       - 'min' (float or None): Minimum allowed value for continuous events (or None if unspecified).
                       - 'max' (float or None): Maximum allowed value for continuous events (or None if unspecified).
        stats (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                      statistical data for the event, including:
                      - 'mean' (float): Mean value for the event.
                      - 'std_dev' (float): Standard deviation for the event.

    Returns:
        list: A list of inconsistency messages, where each message is a string describing a specific inconsistency 
              between the events and stats data. Returns an empty list if no inconsistencies are found.

    Notes:
        - The function checks that the events listed in both `events` and `stats` are identical.
        - For continuous events with specified minimum and maximum values, it verifies if the mean in `stats` 
          falls within this range. If any inconsistency is found, an appropriate message is added to the list.
        - Prints all found inconsistencies to the console.
    '''

    inconsistencies = []
    
    # Check if both files specify the same events
    event_names = set(events.keys())
    stat_names = set(stats.keys())
    if event_names != stat_names:
        inconsistencies.append("Mismatch in event names between Events and Stats files.")
    
    for event_name in events:
        event = events[event_name]
        if event_name in stats:
            stat = stats[event_name]
            if event['type'] == 'C' and (event['min'] is not None and event['max'] is not None):
                if stat['mean'] < event['min'] or stat['mean'] > event['max']:
                    inconsistencies.append(f"{event_name}: mean is outside of specified min/max range.")

    if inconsistencies:
        print("Inconsistencies found:")
        for inc in inconsistencies:
            print(f"- {inc}")
    else:
        print("No inconsistencies found.")
    
    return inconsistencies


def calculate_intrusion(events, stats, days, threshold=2.0):
    
    '''
    Calculates potential intrusions by monitoring event deviations over a specified number of days, 
    and triggers alerts when deviations exceed a defined threshold.

    Args:
        events (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                       details about the event, including:
                       - 'min' (float): Minimum allowed value for continuous events.
                       - 'weight' (int): A positive integer representing the event's significance.
        stats (dict): A dictionary where each key is an event name and each value is a dictionary containing 
                      statistical data for the event, including:
                      - 'mean' (float): Mean value for the event.
                      - 'std_dev' (float): Standard deviation for the event.
        days (int): The number of days over which to monitor and calculate potential intrusions.
        threshold (float, optional): The threshold score that triggers an alert for an event. Default is 2.0.

    Returns:
        list: A list of tuples, where each tuple contains:
              - `day` (int): The day number (from 1 to `days`).
              - `day_alerts` (list): A list of alert messages for that day if any events exceed the threshold, 
                                     or an empty list if no alerts are triggered.

    Notes:
        - For each event, the function calculates a `score` based on the deviation of the event's mean 
          from its minimum allowed value, weighted by the event's significance (`weight`).
        - Alerts are triggered when the score exceeds the specified `threshold`.
        - All alerts are printed to the console as they are triggered, and a message is printed if no alerts 
          are triggered throughout the monitoring period.
    '''

    alerts = []
    for day in range(1, days + 1):
        day_alerts = []
        print(f"Day {day} alerts:")

        for event_name, event in events.items():
            stat = stats[event_name]
            deviation = abs(stat['mean'] - event['min']) / stat['std_dev'] if stat['std_dev'] else 0
            score = deviation * event['weight']

            if score > threshold:  # Define a threshold to trigger alerts
                alert_msg = f"Alert for {event_name}: Score {score} exceeds threshold"
                day_alerts.append(alert_msg)
                print(alert_msg)

        alerts.append((day, day_alerts))
    
    if not any(day_alerts for _, day_alerts in alerts):
        print("No alerts triggered across the monitoring period.")
        
    return alerts


def get_mean_std(vals):
    '''
    Calculate mean and std dev of a list of interger / float
    '''

    # Calculate mean and standard deviation of the generated values
    mean = statistics.mean(vals)
    std_dev = statistics.stdev(vals)

    return mean, std_dev


def generate_event_data(basestats, total_num_days):
    '''
    Generate events for total_num_days based on the statistics in basestats.
    Returns a list of generated events for each day.
    '''
    event_log = []
    threshold = basestats['Threshold']

    # Generate random values to normalization
    random_discrete_vals = []
    for _ in range(total_num_days):
        random_val = random.randint(0, 100000)
        random_discrete_vals.append(random_val)

    random_cont_vals = []
    for _ in range(total_num_days):
        random_val = random.randint(0, 3000)
        random_cont_vals.append(random_val)

    # Calculate mean and std for continous and discrete datatype for zscore normalization
    cont_mean, cont_std = get_mean_std(random_cont_vals)
    disc_mean, disc_std = get_mean_std(random_discrete_vals)

    # Generate events for each day
    for day in range(1, total_num_days + 1):
        daily_events = {}
        print(f"Generating events for Day {day}...")

        #print(basestats)

        for event_name, stats in basestats.items():
            if event_name == "Threshold":
                continue  # Skip threshold

            # Get event parameters (mean, std_dev, min, max, weight)
            mean_val = stats['mean']
            std_dev = stats['std_dev']
            min_val = stats['min']
            max_val = stats['max']
            weight = stats['weight']
            datatype = stats['type']

            #print (f"event: {event_name} / mean: {mean_val}")

            # Generate a random normalizae value
            if datatype == 'C':  # Continuous events
                zscore = (random_cont_vals[day-1] - cont_mean) / cont_std
                event_value = (zscore * std_dev) + mean_val
                event_value = round(event_value, 2)
            else:  # Discrete events
                zscore = (random_discrete_vals[day-1] - disc_mean) / disc_std
                event_value = (zscore * std_dev) + mean_val
                event_value = round(event_value)

            # Log the event value for the day
            daily_events["Day"] = day
            daily_events[event_name] = event_value

            # Check if this event exceeds the threshold
            deviation = abs(event_value - mean_val) / std_dev if std_dev != 0 else 0
            score = deviation * weight
            
            if score > threshold:
                print(f"Alert: {event_name} score {score} exceeds threshold {threshold} on Day {day}")

        # Append the day's events to the event log
        event_log.append(daily_events)

        # Provide periodic progress for each day (e.g., 17%)
        progress = (day / total_num_days) * 100  # Calculate progress in percentage
        print(f"Day {day} completed, progress {progress:.0f}%")

    print("Event generation completed.")
    for i in event_log:
        print (i)

    return event_log


def cal_livestats(event_log):
    '''
    Calculate mean, standard deviation for event log
    and saves the result to a text file.
    Returns a dictionary with of the statistics.
    '''

    # Initialize a dictionary to hold the values for each event
    event_data = {
        'Logins': [],
        'Time online': [],
        'Emails sent': [],
        'Emails opened': [],
        'Emails deleted': []
    }

    # Populate event_data with values from each day's log
    for daily_log in event_log:
        for event_name in event_data:
            event_data[event_name].append(daily_log[event_name])

    # Calculate mean and standard deviation for each event
    event_stats = {}
    for event_name, values in event_data.items():
        mean = statistics.mean(values)
        std_dev = statistics.stdev(values)
        event_stats[event_name] = {'Mean': mean, 'Std Dev': std_dev}

    # Display results
    print("Event Name\tMean\t\tStd Dev")
    for event_name, stats in event_stats.items():
        print(f"{event_name:<15}\t{stats['Mean']:.2f}\t\t{stats['Std Dev']:.2f}")

    return event_stats


def save_event_log(event_log, event_stats):
    '''
    Save event log and stats as filename#.txt,
    where # is the ID of the simulation event log
    '''
    counter = 0

    if event_log:  # This checks if event_log is not empty
        
        filename = f"event_log{counter}.txt"

        # Save event_log to a text file in a tab-separated format
        with open(filename, 'w') as f:
            # Write header with alignment
            f.write(f"{'Day':<10}\t{'Logins':<10}\t{'Time Online':<10}\t{'Emails sent':<10}\t{'Emails opened':<10}\t{'Emails deleted':<10}\n")
            
            # Write each event's stats with better alignment, handling None values as 0
            for event in event_log:
                # Format the line with the data, replacing None with 0
                line = f"{event['Day']:<10}\t{event['Logins']:<10}\t{event['Time online']:<10}\t{event['Emails sent']:<10}\t{event['Emails opened']:<10}\t{event['Emails deleted']:<10}\n"
                f.write(line)

        print("Successfully save event_log to event_log.txt")
        counter = counter + 1 # increase counter per file saved
    else:
        print(f"Event log is empty.")

    return



if __name__ == "__main__":
    print(f"Starting Intrusion Detection System with {function} mode.")
    events = parse_events(events_file)
    stats = parse_stats(stats_file)
    basestats = cal_basestats(events, stats)
    inconsistencies = validate_consistency(events, stats) # Validate file consistency

    # Generate the event log
    event_log = generate_event_data(basestats, days)

    # Calculate statistic of event log
    event_stats = cal_livestats(event_log)

    # Save event log into a event_log#.txt file
    save_event_log(event_log, event_stats)

    # # If no inconsistencies, proceed with IDS
    # if not inconsistencies:
    #     calculate_intrusion(events, stats, days)

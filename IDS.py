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
                    'Type': event_type,
                    'Min': int(min_val) if min_val else int(0),
                    'Max': int(max_val) if max_val else int(0),
                    'Weight': int(weight)
                }
            else:
                # store in event dictionary
                events[event_name] = {
                    'Type': event_type,
                    'Min': float(min_val) if min_val else 0.0,
                    'Max': float(max_val) if max_val else 0.0,
                    'Weight': int(weight)
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
                'Mean': float(mean),
                'Std_dev': float(std_dev)
            }
            # print(f"File stats: {event_name} -> {stats[event_name]}")

        if stats:  # This checks if stats is not empty
            print(f"Successfully loaded {file_path} file")
        else:
            print(f"Failed to load {file_path} file, stats is empty.")

    return stats

def cal_threshold(stats):
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
    for event_name in stats:
        threshold += stats[event_name]['Weight']

    threshold = threshold * 2 # sum * 2

    #print(f"threshold: {threshold}")
    return threshold
def get_mean_std(vals):
    '''
    Calculate mean and std dev of a list of interger / float
    '''

    # Calculate mean and standard deviation of the generated values
    mean = statistics.mean(vals)
    std_dev = statistics.stdev(vals)

    return mean, std_dev
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
            if event['Type'] == 'C' and (event['Min'] is not None and event['Max'] is not None):
                if stat['Mean'] < event['Min'] or stat['Mean'] > event['Max']:
                    inconsistencies.append(f"{event_name}: mean is outside of specified min/max range.")

    if inconsistencies:
        print("Inconsistencies found:")
        for inc in inconsistencies:
            print(f"- {inc}")
    else:
        print("No inconsistencies found.")
    
    return inconsistencies

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
                'Mean': stat_values['Mean'],
                'Std_dev': stat_values['Std_dev'],
                'Min': events[event_name]['Min'],
                'Max': events[event_name]['Max'],
                'Weight': events[event_name]['Weight'],
                'Type': events[event_name]['Type'],
            }
            basestats[event_name] = combined_entry
            #print(f"Base stats: {event_name} -> {combined_entry}")
        else:
            print(f"Warning: {event_name} found in stats but not in events.")

    return basestats
def save_basestats(basestats):
    if basestats:  # This checks if basestats is not empty
        
        filename = f"sim{counter} baseline.txt"

        # Save basestats to a text file in a tab-separated format
        with open(filename, 'w') as f:
            # Write header with alignment
            f.write(f"{'Event Name':<15}\t{'Mean':<8}\t{'Std Dev':<8}\t{'Min':<8}\t{'Max':<8}\t{'Weight':<8}\t{'Data Type':<8}\n")
            
            # Write each event's stats with better alignment
            for event_name, data in basestats.items():

                # Format continuous data to 2 decimal place
                if basestats[event_name]['Type'] == 'C':
                    line = f"{event_name:<15}\t{data['Mean']:<8}\t{data['Std_dev']:<8}\t{data['Min']:<8.2f}\t{data['Max']:<8.2f}\t{data['Weight']:<8}\t{data['Type']:<8}\n"

                else:
                    line = f"{event_name:<15}\t{data['Mean']:<8}\t{data['Std_dev']:<8}\t{data['Min']:<8}\t{data['Max']:<8}\t{data['Weight']:<8}\t{data['Type']:<8}\n"

                f.write(line)

        print(f"Successfully save overall stats as {filename}")
    else:
        print(f"Basestats is empty.")

    return

def generate_event_data(basestats, total_num_days):
    '''
    Generate events for total_num_days based on the statistics in basestats.
    Returns a list of generated dictionary, events for each day.
    '''
    event_log = []
    threshold = cal_threshold(basestats)

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

            # Get event parameters (mean, std_dev, min, max, weight)
            mean_val = stats['Mean']
            std_dev = stats['Std_dev']
            weight = stats['Weight']
            min_val = stats['Min']
            max_val = stats['Max']
            datatype = stats['Type']

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

    print("Event generation completed.")
    # for i in event_log:
    #     print (i)

    return event_log
def save_event_log(event_log):
    '''
    Save event log and stats as filename#.txt,
    where # is the ID of the simulation event log
    '''

    if event_log:  # This checks if event_log is not empty
        
        filename = f"sim{counter} event_log.txt"

        # Save event_log to a text file in a tab-separated format
        with open(filename, 'w') as f:
            # Write event log header with alignment
            f.write(f"{'Day':<10}\t{'Logins':<10}\t{'Time Online':<10}\t{'Emails sent':<10}\t{'Emails opened':<10}\t{'Emails deleted':<10}\n")
            
            # Write each event's stats with better alignment
            for event in event_log:
                # Format the line with the data
                line = f"{event['Day']:<10}\t{event['Logins']:<10}\t{event['Time online']:<10}\t{event['Emails sent']:<10}\t{event['Emails opened']:<12}\t{event['Emails deleted']:<10}\n"
                f.write(line)

        print(f"Successfully save event logs as {filename}")

    else:
        print(f"Event log is empty.")

    return

def analysis_events(event_log, basestats):
    '''
    Calculate mean, standard deviation for each event
    Calculate sum of daily value
    Returns event_stats, daily_total dictionary of dictionary
    '''

    # Initialize a dictionary to hold the values for each event
    event_data = {
        'Logins': [],
        'Time online': [],
        'Emails sent': [],
        'Emails opened': [],
        'Emails deleted': []
    }
   
    daily_total = {}    # Dictionary to store daily totals

    # Populate event_data with values from each day's log
    for daily_log in event_log:
        # Calculate the daily total event value
        day = daily_log['Day']
        daily_total[day] = sum(value for key, value in daily_log.items() if key != 'Day')

        for event_name in event_data:
            event_data[event_name].append(daily_log[event_name])

    # Calculate mean and standard deviation for each event
    event_stats = {}
    for event_name, values in event_data.items():
        mean = statistics.mean(values)
        std_dev = statistics.stdev(values)
        std_dev = round(std_dev,2)
        event_stats[event_name] = {'Mean': mean, 'Std Dev': std_dev, 'Weight': basestats[event_name]['Weight']}

    # # Display results
    # print("Event Name\tMean\t\tStd Dev")
    # for event_name, stats in event_stats.items():
    #     print(f"{event_name:<15}\t{stats['Mean']:.2f}\t\t{stats['Std Dev']:.2f}")

    return event_stats, daily_total
def save_analysis_stats(event_stats):
    '''
    Save event stats as filename#.txt,
    where # is the ID of the simulation event log
    '''
    if event_log:  # This checks if event_log is not empty
        
        filename = f"sim{counter} event_livestats.txt"

        # Save event_log to a text file in a tab-separated format
        with open(filename, 'w') as f:
            # Write event stats header with alignment
            f.write(f"{'Event Names':<15}\t{'Mean':<10}\t{'Std Dev':<10}\t{'Weight':<10}\n")
            
            for event_name, stats in event_stats.items():
                # Format the line with the data
                line = f"{event_name:<15}\t{stats['Mean']:<10.2f}\t{stats['Std Dev']:<10.2f}\t{stats['Weight']:<10}\n"
                f.write(line)

        print(f"Successfully save event live statistic as {filename}")

    else:
        print(f"Event log is empty.")

    return
def save_daily_total(daily_total):
    '''
    Save daily total as filename#.txt,
    where # is the ID of the simulation event log
    '''
    filename = f"sim{counter} daily_total.txt"

    # Write the data to a text file
    with open(filename, 'w') as f:

        # Write the header
        f.write(f"{'Days':<8}{'Total':<8}\n")
        
        # Write each day and total with alignment
        for day, total in daily_total.items():
            f.write(f"{day:<8}{total:<8.2f}\n")

    print(f"Successfully save daily total as {filename}")

def cal_dailycounter(event_log, event_stats, threshold):
    
    '''
    Calculates daily anomally and total daily anomally counter,
    anommally counter is user for dectecting data anomally.
    Event anomally counter is calculated by  (abs((event mean) - event value) / event std) * weight
    Daily anomally counter is define as sum of daily event anomally counter
    '''
    
    # Calculate anomalies
    daily_anomaly = []

    for day_data in event_log:
        day = int(day_data['Day'])
        #print(f"Analysis Day {day}:...")

        # Initialize the day's anomaly data
        event_anomaly = {'Day': day}
        event_flag = 'Okay'
        anomaly_sum = 0

        # Iterate over each event in the daily log (skip 'Day' key)
        for event_name, event_value in day_data.items():
            if event_name == 'Day': 
                continue

            # Get stats values for the current event
            if event_name in event_stats:
                stat_values = event_stats[event_name]
                mean = stat_values['Mean']
                std_dev = stat_values['Std Dev']
                weight = stat_values['Weight']

                # Calculate anomaly counter for each event
                anomaly_score = (abs(mean - event_value) / std_dev) * weight
                event_anomaly[event_name] = anomaly_score
                anomaly_sum += anomaly_score
            else:
                print(f"Warning: Event '{event_name}' not found in stats.")

        # Add sum of anomalies to the day's anomaly data and detect any anomally
        if (anomaly_sum > threshold):
            event_flag = 'Flagged'

        event_anomaly['Total Anomally'] = anomaly_sum
        event_anomaly['Status'] = event_flag

        daily_anomaly.append(event_anomaly)


    # # Display results in the format of event_log
    # for day_anomaly in daily_anomaly:
    #     print(day_anomaly)
    return daily_anomaly
def save_dailycounter(dailycounter, threshold):
    '''
    Save daily counter as filename#.txt,
    where # is the ID of the simulation event log
    '''

    if dailycounter:  # This checks if daily counter is not empty
        
        filename = f"sim{counter} event_dailycounter.txt"

        # Save event_log to a text file in a tab-separated format
        with open(filename, 'w') as f:
            # Write event log header with alignment
            f.write(f"{'Threshold':<10}{threshold:<5}\n")

            # Write event log header with alignment
            f.write(f"{'Day':<5}\t{'Logins':<20}\t{'Time Online':<20}\t{'Emails sent':<20}\t{'Emails opened':<20}\t{'Emails deleted':<20}\t{'Total Anomally':<20}\t{'Status':<20}\n")
            
            # Write each event's stats with better alignment
            for event in dailycounter:
                if (event == 'Threshold'): continue

                # Format the line with the data
                line = f"{event['Day']:<5}\t{event['Logins']:<20}\t{event['Time online']:<20}\t{event['Emails sent']:<20}\t{event['Emails opened']:<20}\t{event['Emails deleted']:<20}\t{event['Total Anomally']:<20}\t{event['Status']:<20}\n"
                f.write(line)

        print(f"Successfully save daily counter as {filename}")

    else:
        print(f"Daily counter is empty.")

    return


if __name__ == "__main__":
    print(f"Starting Intrusion Detection System with {function} mode.")
    events = parse_events(events_file)  # read event file
    stats = parse_stats(stats_file)     # read stats file

    inconsistencies = validate_consistency(events, stats)   # Validate file consistency
    basestats = cal_basestats(events, stats)                # get combine event and stats file and save as basestats.txt
    save_basestats(basestats)                               # Save baseline stats into a baseline#.txt file
   
    print(f"Generating event log for {days} number of days...")
    event_log = generate_event_data(basestats, days)        # Generate the event log
    save_event_log(event_log)                               # Save event log into a event_log#.txt file
    
    print(f"Analysing event logs...")
    event_stats, daily_total = analysis_events(event_log, basestats)    # Analyise statistic of event log
    save_analysis_stats(event_stats)                                    # Save stats into a event_stat#.txt file
    save_daily_total(daily_total)                                       # Save daily total into a daily_total#.txt file

    # testing anomally detection
    threshold = cal_threshold(event_stats)
    dailycounter = cal_dailycounter(event_log, event_stats, threshold)
    save_dailycounter(dailycounter, threshold)

    counter = counter + 1 # increase counter per generation

    while (True):
        user_decision = input("Enter 'q' to quit or press enter to continue: ")
        if user_decision == 'q': break

        new_statsfile = input("Enter new stats filename: ")
        days = int(input("Enter number of days: "))

        stats = parse_stats(new_statsfile)                      # read new stats file
        basestats = cal_basestats(events, stats)                # get combine event and stats file and save as basestats.txtprint(f"Generating event log for {days} number of days...")
        save_basestats(basestats)                               # Save baseline stats into a baseline.txt file
        
        event_log = generate_event_data(basestats, days)        # Generate the event log
        save_event_log(event_log)                               # Save event log into a event_log.txt file
        
        print(f"Analysing event logs...")
        event_stats, daily_total = analysis_events(event_log, basestats)# Analyise statistic of event log
        save_analysis_stats(event_stats)                                # Save stats into a event_stat.txt file
        save_daily_total(daily_total)                                   # Save daily total into a daily_total.txt file
        
        
        # testing anomally detection
        threshold = cal_threshold(event_stats)
        dailycounter = cal_dailycounter(event_log, event_stats, threshold)
        save_dailycounter(dailycounter, threshold)

        counter = counter + 1 # increase counter per generation


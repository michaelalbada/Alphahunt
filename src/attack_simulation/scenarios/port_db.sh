PARENT_DIR="./src/attack_simulation/scenarios/agentdefender/csv_database"  

if [ ! -d "$PARENT_DIR" ]; then  
    echo "Parent directory $PARENT_DIR does not exist."  
    exit 1  
fi  
 
for dir in "$PARENT_DIR"/*/ ; do  

    if [ -d "$dir" ]; then  

        dirname="${dir%/}"  
        dirname="${dirname##*/}" 
          
        echo "----------------------------------------"  
        echo "Processing folder: $dirname"  

        echo "Running map_kc7_to_defender for $dirname..."  
        python3 -m src.attack_simulation.scenarios.map_kc7_to_defender --scenario "$dirname"  
           
        if [ $? -ne 0 ]; then  
            echo "Error: map_kc7_to_defender failed for $dirname"  
            echo "Skipping to the next folder."  
            continue  
        fi  

        echo "Running db_to_csv for $dirname..."  
        python3 -m src.attack_simulation.scenarios.db_to_csv --folder "$dirname"  
          
        if [ $? -ne 0 ]; then  
            echo "Error: db_to_csv failed for $dirname"  
            echo "Skipping to the next folder."  
            continue  
        fi  

        echo "Successfully processed $dirname"  
    fi  
done  

echo "----------------------------------------"  
echo "All folders have been processed."  
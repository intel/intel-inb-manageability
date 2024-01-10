def reset_files(filepath, file_type="txt"):
    with open(filepath, "w") as output_file:
        if file_type == "txt":
            output_file.write("")
        elif file_type == "json":
            output_file.write(json.dumps({}))
        else:
            log.error("ERROR: Invalid file type")

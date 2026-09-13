db_file := "sboms.db"
backup_dir := "backups"
protocol_dir := "protocol"

backup:
    timestamp="$(date +"%Y%m%d_%H%M%S")"; \
    commit="$(git rev-parse --short HEAD)"; \
    backup="TIME_${timestamp}_COMMIT_${commit}"; \
    mkdir -p "{{backup_dir}}/$backup"; \
    cp "{{db_file}}" "{{backup_dir}}/$backup/"; \
    cp -r "{{protocol_dir}}" "{{backup_dir}}/$backup/"; \
    echo "Backup created at {{backup_dir}}/$backup/"

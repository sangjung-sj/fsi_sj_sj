/* 렌더 메인스레드를 영구 블록 → load 이벤트 미발생 → 렌더 타임아웃 → job failed */
while (true) { var _ = Math.random() * Date.now(); }

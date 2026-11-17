// 入力例チップと削除確認だけの小さなスクリプト
document.addEventListener("DOMContentLoaded", function () {
  var input = document.querySelector("#query");

  document.querySelectorAll("[data-sample]").forEach(function (button) {
    button.addEventListener("click", function () {
      if (!input) return;
      input.value = button.getAttribute("data-sample");
      input.focus();
    });
  });

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var message = form.getAttribute("data-confirm");
      if (message && !window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
});

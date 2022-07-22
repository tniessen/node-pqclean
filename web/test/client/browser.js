((scope) => {
  'use strict';

  function into(tag, where) {
    let elem = document.createElement(tag);
    where.appendChild(elem);
    return elem;
  }

  const testListView = into('ul', document.body);
  const views = new Map();

  scope.onTestStart = (name) => {
    const testView = into('li', testListView);
    views.set(name, testView);
    testView.textContent = name;
    testView.style.color = 'orange';
    into('ol', testView);
  };

  scope.onTestProgress = (name, newStage) => {
    const list = views.get(name).querySelector('ol');
    const previousItems = [...list.querySelectorAll('li')];
    if (previousItems.length !== 0) {
      previousItems[previousItems.length - 1].style.color = 'green';
    }
    const item = into('li', list);
    item.textContent = newStage;
    item.style.color = 'inherit';
  };

  scope.onTestDone = (name) => {
    views.get(name).style.color = 'green';
  };
})(globalThis);
